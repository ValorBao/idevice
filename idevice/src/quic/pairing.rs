//! Remote Pairing session used to ask a device for a QUIC tunnel listener.
//!
//! This speaks the `_remotepairing._tcp` socket: `RPPairing` frames of JSON,
//! pair-verify for an existing host record, then an encrypted `createListener`
//! request. Pair-setup (the first-time trust dialog) is not implemented.
//!
//! Keep the session alive while the QUIC tunnel is in use. Dropping it closes
//! the control connection the device associates with the listener.

use std::{net::SocketAddr, path::Path};

use base64::Engine;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Tag};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha512;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey};

use super::QuicIdentity;
use crate::IdeviceError;

use super::tlv;

const MAGIC: &[u8] = b"RPPairing";
const WIRE_PROTOCOL_VERSION: u64 = 19;
const NONCE_PV_MSG03: &[u8] = b"\x00\x00\x00\x00PV-Msg03";

/// Host identity persisted across Remote Pairing sessions.
///
/// `private_key` and `public_key` are the raw 32-byte Ed25519 seed and
/// verifying key. `identifier` is the host id that was signed during pairing.
#[derive(Clone)]
pub struct PairingRecord {
    pub identifier: String,
    pub public_key: [u8; 32],
    pub private_key: [u8; 32],
}

impl std::fmt::Debug for PairingRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingRecord")
            .field("identifier", &self.identifier)
            .field("public_key", &hex_prefix(&self.public_key))
            .finish_non_exhaustive()
    }
}

impl PairingRecord {
    /// Creates a new host identity. `identifier` must stay stable for this host.
    pub fn generate(identifier: impl Into<String>) -> Self {
        let mut rng = OsRng;
        let signing = SigningKey::generate(&mut rng);
        Self {
            identifier: identifier.into(),
            public_key: signing.verifying_key().to_bytes(),
            private_key: signing.to_bytes(),
        }
    }

    /// Reads a plist dictionary with `identifier`, `public_key`, and `private_key`.
    pub fn from_plist(value: &plist::Value) -> Result<Self, IdeviceError> {
        let dict = value
            .as_dictionary()
            .ok_or_else(|| IdeviceError::Quic("pairing record is not a dictionary".to_string()))?;
        let identifier = dict
            .get("identifier")
            .and_then(|value| value.as_string())
            .ok_or_else(|| IdeviceError::Quic("pairing record is missing identifier".to_string()))?
            .to_string();
        let public_key = key_bytes(dict.get("public_key"), "public_key")?;
        let private_key = key_bytes(dict.get("private_key"), "private_key")?;
        Ok(Self {
            identifier,
            public_key,
            private_key,
        })
    }

    /// Serializes this record as a plist dictionary.
    pub fn to_plist(&self) -> plist::Value {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "identifier".into(),
            plist::Value::String(self.identifier.clone()),
        );
        dict.insert(
            "public_key".into(),
            plist::Value::Data(self.public_key.to_vec()),
        );
        dict.insert(
            "private_key".into(),
            plist::Value::Data(self.private_key.to_vec()),
        );
        plist::Value::Dictionary(dict)
    }

    /// Loads a pairing record from an XML or binary plist file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, IdeviceError> {
        let value: plist::Value = plist::from_file(path)?;
        Self::from_plist(&value)
    }

    /// Writes this record as an XML plist.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), IdeviceError> {
        self.to_plist().to_file_xml(path)?;
        Ok(())
    }

    fn signing_key(&self) -> Result<SigningKey, IdeviceError> {
        let key = SigningKey::from_bytes(&self.private_key);
        if key.verifying_key().to_bytes() != self.public_key {
            return Err(IdeviceError::Quic(
                "pairing record public key does not match the private key".to_string(),
            ));
        }
        Ok(key)
    }
}

/// Pair-verified Remote Pairing control connection.
pub struct RemotePairingSession<S> {
    stream: S,
    peer: SocketAddr,
    sequence: u64,
    encrypted_sequence: u64,
    /// X25519 shared secret from pair-verify. This is also the TLS-PSK for a
    /// TCP tunnel on iOS 18.2+.
    encryption_key: Option<[u8; 32]>,
    client_key: Option<[u8; 32]>,
    server_key: Option<[u8; 32]>,
}

impl<S> std::fmt::Debug for RemotePairingSession<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemotePairingSession")
            .field("peer", &self.peer)
            .field("paired", &self.encryption_key.is_some())
            .finish_non_exhaustive()
    }
}

impl RemotePairingSession<tokio::net::TcpStream> {
    /// Connects to `_remotepairing._tcp` and completes pair-verify.
    pub async fn connect(addr: SocketAddr, record: &PairingRecord) -> Result<Self, IdeviceError> {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        let mut session = Self::new(stream, addr);
        session.pair_verify(record).await?;
        Ok(session)
    }
}

impl<S> RemotePairingSession<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Wraps an already-connected Remote Pairing socket.
    pub fn new(stream: S, peer: SocketAddr) -> Self {
        Self {
            stream,
            peer,
            sequence: 0,
            encrypted_sequence: 0,
            encryption_key: None,
            client_key: None,
            server_key: None,
        }
    }

    /// Address of the device control connection.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// X25519 shared secret established by pair-verify.
    pub fn encryption_key(&self) -> Option<&[u8; 32]> {
        self.encryption_key.as_ref()
    }

    /// Proves this host was paired before and derives the session keys.
    pub async fn pair_verify(&mut self, record: &PairingRecord) -> Result<(), IdeviceError> {
        let signing = record.signing_key()?;
        self.send_plain(&serde_json::json!({
            "request": {
                "_0": {
                    "handshake": {
                        "_0": {
                            "hostOptions": {"attemptPairVerify": true},
                            "wireProtocolVersion": WIRE_PROTOCOL_VERSION
                        }
                    }
                }
            }
        }))
        .await?;
        let handshake = self.recv_plain().await?;
        if handshake.pointer("/response/_1/handshake/_0").is_none() {
            return Err(IdeviceError::Quic(format!(
                "unexpected pair-verify handshake response: {handshake}"
            )));
        }

        let ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let local_public = PublicKey::from(&ephemeral);
        let start = tlv::encode(&[
            (tlv::STATE, &[0x01]),
            (tlv::PUBLIC_KEY, local_public.as_bytes()),
        ]);
        self.send_pairing_data(&start, true).await?;
        let peer_tlv = tlv::decode(&self.recv_pairing_data().await?)?;
        if peer_tlv.contains_key(&tlv::ERROR) {
            self.send_pair_verify_failed().await?;
            return Err(IdeviceError::Quic(
                "device rejected pair-verify".to_string(),
            ));
        }
        let peer_public_bytes = peer_tlv.get(&tlv::PUBLIC_KEY).ok_or_else(|| {
            IdeviceError::Quic("pair-verify response is missing the device public key".to_string())
        })?;
        let peer_public_bytes: [u8; 32] =
            peer_public_bytes.as_slice().try_into().map_err(|_| {
                IdeviceError::Quic("device X25519 public key is not 32 bytes".to_string())
            })?;
        let shared = ephemeral.diffie_hellman(&PublicKey::from(peer_public_bytes));
        let shared_bytes = shared.to_bytes();
        let verify_key = hkdf32(
            Some(b"Pair-Verify-Encrypt-Salt"),
            &shared_bytes,
            b"Pair-Verify-Encrypt-Info",
        )?;

        let mut signed = Vec::with_capacity(64 + record.identifier.len());
        signed.extend_from_slice(local_public.as_bytes());
        signed.extend_from_slice(record.identifier.as_bytes());
        signed.extend_from_slice(&peer_public_bytes);
        let signature = signing.sign(&signed).to_bytes();
        let proof = tlv::encode(&[
            (tlv::IDENTIFIER, record.identifier.as_bytes()),
            (tlv::SIGNATURE, &signature),
        ]);
        let encrypted = aead_encrypt(&verify_key, NONCE_PV_MSG03, &proof)?;
        let state3 = tlv::encode(&[(tlv::STATE, &[0x03]), (tlv::ENCRYPTED_DATA, &encrypted)]);
        self.send_pairing_data(&state3, false).await?;
        let result = tlv::decode(&self.recv_pairing_data().await?)?;
        if result.contains_key(&tlv::ERROR) {
            self.send_pair_verify_failed().await?;
            return Err(IdeviceError::Quic(
                "device rejected the pair-verify proof".to_string(),
            ));
        }

        self.client_key = Some(hkdf32(None, &shared_bytes, b"ClientEncrypt-main")?);
        self.server_key = Some(hkdf32(None, &shared_bytes, b"ServerEncrypt-main")?);
        self.encryption_key = Some(shared_bytes);
        Ok(())
    }

    /// Opens the QUIC listener and connects the tunnel.
    ///
    /// The session has to stay alive for the life of the tunnel.
    pub async fn open_quic_tunnel(
        &mut self,
        identity: &QuicIdentity,
        options: super::QuicTunnelOptions,
    ) -> Result<super::QuicTunnel, IdeviceError> {
        let port = self.create_quic_listener(identity).await?;
        let mut addr = self.peer;
        addr.set_port(port);
        super::QuicTunnel::connect(addr, identity, options).await
    }

    /// Asks the device to open a QUIC listener for `identity` and returns its UDP port.
    pub async fn create_quic_listener(
        &mut self,
        identity: &QuicIdentity,
    ) -> Result<u16, IdeviceError> {
        let response = self.encrypted_request(identity.listener_request()).await?;
        let port = response
            .pointer("/createListener/port")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                IdeviceError::Quic(format!("createListener response has no port: {response}"))
            })?;
        u16::try_from(port).map_err(|_| {
            IdeviceError::Quic(format!("createListener port {port} does not fit in u16"))
        })
    }

    /// Pair-verified control request, encrypted with the client session key.
    pub async fn encrypted_request(
        &mut self,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, IdeviceError> {
        let client_key = self.client_key.ok_or_else(|| {
            IdeviceError::Quic("encrypted request sent before pair-verify".to_string())
        })?;
        let server_key = self.server_key.ok_or_else(|| {
            IdeviceError::Quic("encrypted request sent before pair-verify".to_string())
        })?;
        let nonce = encrypted_nonce(self.encrypted_sequence);
        let plaintext = serde_json::to_vec(&request)?;
        let ciphertext = aead_encrypt(&client_key, &nonce, &plaintext)?;
        let response = self
            .roundtrip(&serde_json::json!({
                "message": {"streamEncrypted": {"_0": b64(&ciphertext)}},
                "originatedBy": "host",
                "sequenceNumber": self.sequence
            }))
            .await?;
        self.encrypted_sequence += 1;

        let encoded = response
            .pointer("/message/streamEncrypted/_0")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                IdeviceError::Quic(format!(
                    "encrypted response is missing ciphertext: {response}"
                ))
            })?;
        let mut received = b64_decode(encoded)?;
        let plain = aead_decrypt(&server_key, &nonce, &mut received)?;
        let parsed: serde_json::Value = serde_json::from_slice(plain)?;
        let body = parsed.pointer("/response/_1").cloned().ok_or_else(|| {
            IdeviceError::Quic(format!("encrypted response has no response/_1: {parsed}"))
        })?;
        if let Some(message) = body.pointer("/errorExtended/_0/userInfo/NSLocalizedDescription") {
            return Err(IdeviceError::Quic(format!("device error: {message}")));
        }
        Ok(body)
    }

    async fn send_pairing_data(
        &mut self,
        tlv: &[u8],
        start_new_session: bool,
    ) -> Result<(), IdeviceError> {
        self.send_plain(&serde_json::json!({
            "event": {
                "_0": {
                    "pairingData": {
                        "_0": {
                            "data": b64(tlv),
                            "kind": "verifyManualPairing",
                            "startNewSession": start_new_session
                        }
                    }
                }
            }
        }))
        .await
    }

    async fn recv_pairing_data(&mut self) -> Result<Vec<u8>, IdeviceError> {
        let payload = self.recv_plain().await?;
        let event = payload.pointer("/event/_0").ok_or_else(|| {
            IdeviceError::Quic(format!("pairing response has no event: {payload}"))
        })?;
        if let Some(rejected) = event.get("pairingRejectedWithError") {
            return Err(IdeviceError::Quic(format!("pairing rejected: {rejected}")));
        }
        let encoded = event
            .pointer("/pairingData/_0/data")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                IdeviceError::Quic(format!("pairing response has no data: {payload}"))
            })?;
        b64_decode(encoded)
    }

    async fn send_pair_verify_failed(&mut self) -> Result<(), IdeviceError> {
        self.send_plain(&serde_json::json!({
            "event": {"_0": {"pairVerifyFailed": {}}}
        }))
        .await
    }

    async fn send_plain(&mut self, payload: &serde_json::Value) -> Result<(), IdeviceError> {
        self.send(&serde_json::json!({
            "message": {"plain": {"_0": payload}},
            "originatedBy": "host",
            "sequenceNumber": self.sequence
        }))
        .await?;
        self.sequence += 1;
        Ok(())
    }

    async fn recv_plain(&mut self) -> Result<serde_json::Value, IdeviceError> {
        let message = self.recv().await?;
        message
            .pointer("/message/plain/_0")
            .cloned()
            .ok_or_else(|| IdeviceError::Quic(format!("response has no plain payload: {message}")))
    }

    async fn roundtrip(
        &mut self,
        message: &serde_json::Value,
    ) -> Result<serde_json::Value, IdeviceError> {
        self.send(message).await?;
        self.recv().await
    }

    async fn send(&mut self, message: &serde_json::Value) -> Result<(), IdeviceError> {
        let body = serde_json::to_vec(message)?;
        if body.len() > u16::MAX as usize {
            return Err(IdeviceError::Quic(
                "remote pairing message exceeds u16 length".to_string(),
            ));
        }
        self.stream.write_all(MAGIC).await?;
        self.stream
            .write_all(&(body.len() as u16).to_be_bytes())
            .await?;
        self.stream.write_all(&body).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<serde_json::Value, IdeviceError> {
        let mut magic = [0u8; MAGIC.len()];
        self.stream.read_exact(&mut magic).await?;
        if magic != MAGIC {
            return Err(IdeviceError::Quic(
                "remote pairing response has the wrong magic".to_string(),
            ));
        }
        let mut len_buf = [0u8; 2];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        self.stream.read_exact(&mut body).await?;
        Ok(serde_json::from_slice(&body)?)
    }
}

fn key_bytes(value: Option<&plist::Value>, name: &str) -> Result<[u8; 32], IdeviceError> {
    let data = value
        .and_then(|value| value.as_data())
        .ok_or_else(|| IdeviceError::Quic(format!("pairing record {name} is missing")))?;
    data.try_into().map_err(|_| {
        IdeviceError::Quic(format!(
            "pairing record {name} must be 32 bytes, got {}",
            data.len()
        ))
    })
}

fn hkdf32(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> Result<[u8; 32], IdeviceError> {
    let hk = Hkdf::<Sha512>::new(salt, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|error| IdeviceError::Quic(format!("hkdf failed: {error}")))?;
    Ok(okm)
}

fn encrypted_nonce(sequence: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&sequence.to_le_bytes());
    nonce
}

fn aead_encrypt(key: &[u8; 32], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, IdeviceError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = chacha20poly1305::Nonce::from_slice(nonce);
    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce, b"", &mut buffer)
        .map_err(|_| IdeviceError::Quic("chacha20-poly1305 encryption failed".to_string()))?;
    buffer.extend_from_slice(tag.as_slice());
    Ok(buffer)
}

fn aead_decrypt<'a>(
    key: &[u8; 32],
    nonce: &[u8],
    buffer: &'a mut [u8],
) -> Result<&'a [u8], IdeviceError> {
    if buffer.len() < 16 {
        return Err(IdeviceError::Quic(
            "ciphertext is shorter than the poly1305 tag".to_string(),
        ));
    }
    let split = buffer.len() - 16;
    let (message, tag_bytes) = buffer.split_at_mut(split);
    let tag = Tag::from_slice(tag_bytes);
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = chacha20poly1305::Nonce::from_slice(nonce);
    cipher
        .decrypt_in_place_detached(nonce, b"", message, tag)
        .map_err(|_| IdeviceError::Quic("chacha20-poly1305 decryption failed".to_string()))?;
    let len = message.len();
    Ok(&buffer[..len])
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64_decode(text: &str) -> Result<Vec<u8>, IdeviceError> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|error| IdeviceError::Quic(format!("remote pairing base64: {error}")))
}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(4)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn pairing_record_roundtrips_through_plist() {
        let record = PairingRecord::generate("host-identifier");
        let restored = PairingRecord::from_plist(&record.to_plist()).unwrap();
        assert_eq!(restored.identifier, record.identifier);
        assert_eq!(restored.public_key, record.public_key);
        assert_eq!(restored.private_key, record.private_key);
    }

    async fn serve(mut socket: tokio::net::TcpStream, record: &PairingRecord) -> u16 {
        let handshake = read_frame(&mut socket).await;
        assert_eq!(handshake["sequenceNumber"].as_u64(), Some(0));
        write_frame(
            &mut socket,
            &serde_json::json!({
                "message": {"plain": {"_0": {
                    "response": {"_1": {"handshake": {"_0": {"accepted": true}}}}
                }}},
                "originatedBy": "device",
                "sequenceNumber": 0
            }),
        )
        .await;

        let start = read_frame(&mut socket).await;
        let start_tlv = tlv::decode(&decode_pairing_data(&start)).unwrap();
        let client_public = PublicKey::from(
            <[u8; 32]>::try_from(start_tlv.get(&tlv::PUBLIC_KEY).unwrap().as_slice()).unwrap(),
        );
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&secret);
        let shared = secret.diffie_hellman(&client_public).to_bytes();
        let reply = tlv::encode(&[
            (tlv::STATE, &[0x02]),
            (tlv::PUBLIC_KEY, server_public.as_bytes()),
            (tlv::ENCRYPTED_DATA, b"ignored-by-client"),
        ]);
        write_pairing(&mut socket, &reply).await;

        let proof = read_frame(&mut socket).await;
        let proof_tlv = tlv::decode(&decode_pairing_data(&proof)).unwrap();
        let verify_key = hkdf32(
            Some(b"Pair-Verify-Encrypt-Salt"),
            &shared,
            b"Pair-Verify-Encrypt-Info",
        )
        .unwrap();
        let mut encrypted = proof_tlv.get(&tlv::ENCRYPTED_DATA).unwrap().clone();
        let plain = aead_decrypt(&verify_key, NONCE_PV_MSG03, &mut encrypted).unwrap();
        let inner = tlv::decode(plain).unwrap();
        assert_eq!(
            inner.get(&tlv::IDENTIFIER).unwrap(),
            record.identifier.as_bytes()
        );
        let signature =
            ed25519_dalek::Signature::from_slice(inner.get(&tlv::SIGNATURE).unwrap()).unwrap();
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(&record.public_key).unwrap();
        let mut signed = Vec::new();
        signed.extend_from_slice(client_public.as_bytes());
        signed.extend_from_slice(record.identifier.as_bytes());
        signed.extend_from_slice(server_public.as_bytes());
        verifying.verify_strict(&signed, &signature).unwrap();
        write_pairing(&mut socket, &tlv::encode(&[(tlv::STATE, &[0x04])])).await;

        let request = read_frame(&mut socket).await;
        let client_key = hkdf32(None, &shared, b"ClientEncrypt-main").unwrap();
        let server_key = hkdf32(None, &shared, b"ServerEncrypt-main").unwrap();
        let mut ciphertext = b64_decode(
            request["message"]["streamEncrypted"]["_0"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let plain = aead_decrypt(&client_key, &encrypted_nonce(0), &mut ciphertext).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(plain).unwrap();
        assert_eq!(
            parsed["request"]["_0"]["createListener"]["transportProtocolType"].as_str(),
            Some("quic")
        );
        let response = serde_json::json!({
            "response": {"_1": {"createListener": {"port": 54321}}}
        });
        let encrypted = aead_encrypt(
            &server_key,
            &encrypted_nonce(0),
            &serde_json::to_vec(&response).unwrap(),
        )
        .unwrap();
        write_frame(
            &mut socket,
            &serde_json::json!({
                "message": {"streamEncrypted": {"_0": b64(&encrypted)}},
                "originatedBy": "device",
                "sequenceNumber": 3
            }),
        )
        .await;
        54321
    }

    fn decode_pairing_data(message: &serde_json::Value) -> Vec<u8> {
        b64_decode(
            message["message"]["plain"]["_0"]["event"]["_0"]["pairingData"]["_0"]["data"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
    }

    async fn read_frame(socket: &mut tokio::net::TcpStream) -> serde_json::Value {
        let mut magic = [0u8; 9];
        socket.read_exact(&mut magic).await.unwrap();
        assert_eq!(&magic, MAGIC);
        let mut len_buf = [0u8; 2];
        socket.read_exact(&mut len_buf).await.unwrap();
        let mut body = vec![0u8; u16::from_be_bytes(len_buf) as usize];
        socket.read_exact(&mut body).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    async fn write_frame(socket: &mut tokio::net::TcpStream, message: &serde_json::Value) {
        let body = serde_json::to_vec(message).unwrap();
        socket.write_all(MAGIC).await.unwrap();
        socket
            .write_all(&(body.len() as u16).to_be_bytes())
            .await
            .unwrap();
        socket.write_all(&body).await.unwrap();
        socket.flush().await.unwrap();
    }

    async fn write_pairing(socket: &mut tokio::net::TcpStream, tlv: &[u8]) {
        write_frame(
            socket,
            &serde_json::json!({
                "message": {"plain": {"_0": {
                    "event": {"_0": {"pairingData": {"_0": {"data": b64(tlv)}}}}
                }}},
                "originatedBy": "device",
                "sequenceNumber": 1
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn pair_verify_then_create_quic_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let record = PairingRecord::generate("host-identifier");
        let server_record = record.clone();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            serve(socket, &server_record).await
        });

        let mut session = RemotePairingSession::connect(addr, &record).await.unwrap();
        assert!(session.encryption_key().is_some());
        let identity = QuicIdentity::generate().unwrap();
        let port = session.create_quic_listener(&identity).await.unwrap();
        assert_eq!(port, server.await.unwrap());
    }
}
