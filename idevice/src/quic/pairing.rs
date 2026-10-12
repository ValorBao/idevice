//! Remote Pairing session used to ask a device for a QUIC tunnel listener.
//!
//! This speaks the `_remotepairing._tcp` socket: `RPPairing` frames of JSON,
//! pair-setup for the first trust dialog or pair-verify for an existing host
//! record, then an encrypted `createListener` request.
//!
//! Keep the session alive while the QUIC tunnel is in use. Dropping it closes
//! the control connection the device associates with the listener. Some devices
//! close the socket after pair-setup; save the returned record and pair-verify
//! on a new connection before opening the tunnel.

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
use super::opack;
use super::srp;
use super::tlv;
use crate::IdeviceError;

const MAGIC: &[u8] = b"RPPairing";
const WIRE_PROTOCOL_VERSION: u64 = 19;
const NONCE_PV_MSG03: &[u8] = b"\x00\x00\x00\x00PV-Msg03";
const NONCE_PS_MSG05: &[u8] = b"\x00\x00\x00\x00PS-Msg05";
const NONCE_PS_MSG06: &[u8] = b"\x00\x00\x00\x00PS-Msg06";
const SETUP_KIND: &str = "setupManualPairing";
const VERIFY_KIND: &str = "verifyManualPairing";

/// Options for [`RemotePairingSession::pair_setup`].
#[derive(Debug, Clone)]
pub struct PairSetupOptions {
    /// PIN the device is showing. iOS uses `000000` until the user taps Trust.
    /// Apple TV shows a PIN that has to be entered here.
    pub pin: String,
    /// Name presented on the trust dialog.
    pub hostname: String,
    /// Stable host id signed into the pairing record.
    pub identifier: String,
}

impl PairSetupOptions {
    /// PIN defaults to `000000` and the hostname defaults to `localhost`.
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            pin: "000000".to_string(),
            hostname: "localhost".to_string(),
            identifier: identifier.into(),
        }
    }
}

/// Host identity persisted across Remote Pairing sessions.
///
/// `private_key` and `public_key` are the raw 32-byte Ed25519 seed and
/// verifying key. `identifier` is the host id that was signed during pairing.
#[derive(Clone)]
pub struct PairingRecord {
    pub identifier: String,
    pub public_key: [u8; 32],
    pub private_key: [u8; 32],
    /// Host key from `createRemoteUnlockKey`, when the device returned one.
    pub remote_unlock_host_key: Option<String>,
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
            remote_unlock_host_key: None,
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
        let remote_unlock_host_key = dict
            .get("remote_unlock_host_key")
            .and_then(|value| value.as_string())
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        Ok(Self {
            identifier,
            public_key,
            private_key,
            remote_unlock_host_key,
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
        if let Some(host_key) = &self.remote_unlock_host_key {
            dict.insert(
                "remote_unlock_host_key".into(),
                plist::Value::String(host_key.clone()),
            );
        }
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
    /// Pair-verify stores the 32-byte X25519 secret. Pair-setup stores the
    /// 64-byte SRP session key. Both are the TLS-PSK for an iOS 18.2 TCP tunnel.
    encryption_key: Option<Vec<u8>>,
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

    /// Connects to `_remotepairing._tcp` and runs first-time pair-setup.
    pub async fn pair(
        addr: SocketAddr,
        options: &PairSetupOptions,
    ) -> Result<(Self, PairingRecord), IdeviceError> {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        let mut session = Self::new(stream, addr);
        let record = session.pair_setup(options).await?;
        Ok((session, record))
    }
}

enum PairVerifyOutcome {
    Established,
    Rejected(&'static str),
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

    /// Session secret established by pairing.
    ///
    /// Pair-verify stores the 32-byte X25519 shared secret. Pair-setup stores
    /// the 64-byte SRP session key. Both values are the HKDF input for the
    /// control channel and the TLS-PSK for an iOS 18.2 TCP tunnel.
    pub fn encryption_key(&self) -> Option<&[u8]> {
        self.encryption_key.as_deref()
    }

    /// Proves this host was paired before and derives the session keys.
    pub async fn pair_verify(&mut self, record: &PairingRecord) -> Result<(), IdeviceError> {
        record.signing_key()?;
        self.handshake().await?;
        match self.complete_pair_verify(record).await? {
            PairVerifyOutcome::Established => Ok(()),
            PairVerifyOutcome::Rejected(message) => Err(IdeviceError::Quic(message.to_string())),
        }
    }

    /// Pairs this host for the first time and returns the record to save.
    ///
    /// The call sends the Remote Pairing handshake and a pair-verify attempt.
    /// When the device has no record for this host it rejects that attempt,
    /// and the session continues with SRP-3072 setup. On iOS the PIN is
    /// `000000` and this waits while the device shows the Trust dialog. Apple
    /// TV returns the SRP salt immediately and needs the on-screen PIN in
    /// [`PairSetupOptions::pin`].
    ///
    /// Save the returned record and pass it to [`Self::pair_verify`] on later
    /// connections. The session keys are ready for `createListener` when the
    /// device keeps this socket open.
    pub async fn pair_setup(
        &mut self,
        options: &PairSetupOptions,
    ) -> Result<PairingRecord, IdeviceError> {
        if options.identifier.is_empty() {
            return Err(IdeviceError::Quic(
                "pair-setup identifier is empty".to_string(),
            ));
        }
        self.handshake().await?;
        let throwaway = PairingRecord::generate(&options.identifier);
        match self.complete_pair_verify(&throwaway).await? {
            PairVerifyOutcome::Established => return Ok(throwaway),
            PairVerifyOutcome::Rejected(_) => {}
        }

        let (salt, server_public) = self.request_consent(&options.hostname).await?;
        let session = srp::client_session(&options.pin, &salt, &server_public)?;
        let proof = tlv::encode(&[
            (tlv::STATE, &[0x03]),
            (tlv::PUBLIC_KEY, &session.public),
            (tlv::PROOF, &session.proof),
        ]);
        self.send_pairing_data(&proof, SETUP_KIND, false, Some(&options.hostname))
            .await?;
        let response = tlv::decode(&self.recv_pairing_data().await?)?;
        if response.contains_key(&tlv::ERROR) {
            return Err(IdeviceError::Quic(
                "device rejected the pair-setup proof".to_string(),
            ));
        }
        let server_proof = response.get(&tlv::PROOF).ok_or_else(|| {
            IdeviceError::Quic("pair-setup response is missing the server proof".to_string())
        })?;
        if server_proof != &session.server_proof {
            return Err(IdeviceError::Quic(
                "device SRP proof did not match".to_string(),
            ));
        }

        let mut record = PairingRecord::generate(&options.identifier);
        self.save_pair_record(&record, &session.key, &options.hostname)
            .await?;
        self.install_session_keys(&session.key)?;
        record.remote_unlock_host_key = self.create_remote_unlock().await;
        Ok(record)
    }

    async fn handshake(&mut self) -> Result<(), IdeviceError> {
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
                "unexpected remote pairing handshake response: {handshake}"
            )));
        }
        Ok(())
    }

    async fn complete_pair_verify(
        &mut self,
        record: &PairingRecord,
    ) -> Result<PairVerifyOutcome, IdeviceError> {
        let ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let local_public = PublicKey::from(&ephemeral);
        let start = tlv::encode(&[
            (tlv::STATE, &[0x01]),
            (tlv::PUBLIC_KEY, local_public.as_bytes()),
        ]);
        self.send_pairing_data(&start, VERIFY_KIND, true, None)
            .await?;
        let peer_tlv = tlv::decode(&self.recv_pairing_data().await?)?;
        if peer_tlv.contains_key(&tlv::ERROR) {
            self.send_pair_verify_failed().await?;
            return Ok(PairVerifyOutcome::Rejected("device rejected pair-verify"));
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

        let signing = record.signing_key()?;
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
        self.send_pairing_data(&state3, VERIFY_KIND, false, None)
            .await?;
        let result = tlv::decode(&self.recv_pairing_data().await?)?;
        if result.contains_key(&tlv::ERROR) {
            self.send_pair_verify_failed().await?;
            return Ok(PairVerifyOutcome::Rejected(
                "device rejected the pair-verify proof",
            ));
        }

        self.install_session_keys(&shared_bytes)?;
        Ok(PairVerifyOutcome::Established)
    }

    async fn request_consent(
        &mut self,
        hostname: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), IdeviceError> {
        let request = tlv::encode(&[(tlv::METHOD, &[0x00]), (tlv::STATE, &[0x01])]);
        self.send_pairing_data(&request, SETUP_KIND, true, Some(hostname))
            .await?;
        let event = self.recv_event().await?;
        if let Some(rejected) = event.get("pairingRejectedWithError") {
            return Err(rejection_error(rejected));
        }
        let data = if event.get("awaitingUserConsent").is_some() {
            self.recv_pairing_data().await?
        } else {
            pairing_bytes(&event)?
        };
        let tlv = tlv::decode(&data)?;
        let salt = tlv.get(&tlv::SALT).cloned().ok_or_else(|| {
            IdeviceError::Quic("pair-setup response is missing the salt".to_string())
        })?;
        let server_public = tlv.get(&tlv::PUBLIC_KEY).cloned().ok_or_else(|| {
            IdeviceError::Quic("pair-setup response is missing the server public key".to_string())
        })?;
        Ok((salt, server_public))
    }

    async fn save_pair_record(
        &mut self,
        record: &PairingRecord,
        key: &[u8],
        hostname: &str,
    ) -> Result<(), IdeviceError> {
        let setup_key = hkdf32(
            Some(b"Pair-Setup-Encrypt-Salt"),
            key,
            b"Pair-Setup-Encrypt-Info",
        )?;
        let mut signed = hkdf32(
            Some(b"Pair-Setup-Controller-Sign-Salt"),
            key,
            b"Pair-Setup-Controller-Sign-Info",
        )?
        .to_vec();
        signed.extend_from_slice(record.identifier.as_bytes());
        signed.extend_from_slice(&record.public_key);
        let signature = record.signing_key()?.sign(&signed).to_bytes();
        let info = opack::device_info(&record.identifier, hostname);
        let inner = tlv::encode(&[
            (tlv::IDENTIFIER, record.identifier.as_bytes()),
            (tlv::PUBLIC_KEY, &record.public_key),
            (tlv::SIGNATURE, &signature),
            (tlv::INFO, &info),
        ]);
        let encrypted = aead_encrypt(&setup_key, NONCE_PS_MSG05, &inner)?;
        let outer = tlv::encode(&[(tlv::ENCRYPTED_DATA, &encrypted), (tlv::STATE, &[0x05])]);
        self.send_pairing_data(&outer, SETUP_KIND, false, Some(hostname))
            .await?;
        let response = tlv::decode(&self.recv_pairing_data().await?)?;
        if response.contains_key(&tlv::ERROR) {
            return Err(IdeviceError::Quic(
                "device rejected the pairing record".to_string(),
            ));
        }
        let mut encrypted = response.get(&tlv::ENCRYPTED_DATA).cloned().ok_or_else(|| {
            IdeviceError::Quic("pair-setup response is missing encrypted data".to_string())
        })?;
        aead_decrypt(&setup_key, NONCE_PS_MSG06, &mut encrypted)?;
        Ok(())
    }

    async fn create_remote_unlock(&mut self) -> Option<String> {
        let response = self
            .encrypted_request(serde_json::json!({
                "request": {"_0": {"createRemoteUnlockKey": {}}}
            }))
            .await
            .ok()?;
        response
            .pointer("/createRemoteUnlockKey/hostKey")
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    }

    fn install_session_keys(&mut self, ikm: &[u8]) -> Result<(), IdeviceError> {
        self.client_key = Some(hkdf32(None, ikm, b"ClientEncrypt-main")?);
        self.server_key = Some(hkdf32(None, ikm, b"ServerEncrypt-main")?);
        self.encryption_key = Some(ikm.to_vec());
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
            IdeviceError::Quic("encrypted request sent before pairing".to_string())
        })?;
        let server_key = self.server_key.ok_or_else(|| {
            IdeviceError::Quic("encrypted request sent before pairing".to_string())
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
        kind: &str,
        start_new_session: bool,
        sending_host: Option<&str>,
    ) -> Result<(), IdeviceError> {
        let mut data = serde_json::json!({
            "data": b64(tlv),
            "kind": kind,
            "startNewSession": start_new_session
        });
        if let Some(host) = sending_host {
            data["sendingHost"] = serde_json::Value::String(host.to_string());
        }
        self.send_plain(&serde_json::json!({
            "event": {"_0": {"pairingData": {"_0": data}}}
        }))
        .await
    }

    async fn recv_pairing_data(&mut self) -> Result<Vec<u8>, IdeviceError> {
        pairing_bytes(&self.recv_event().await?)
    }

    async fn recv_event(&mut self) -> Result<serde_json::Value, IdeviceError> {
        let payload = self.recv_plain().await?;
        payload
            .pointer("/event/_0")
            .cloned()
            .ok_or_else(|| IdeviceError::Quic(format!("pairing response has no event: {payload}")))
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

fn pairing_bytes(event: &serde_json::Value) -> Result<Vec<u8>, IdeviceError> {
    if let Some(rejected) = event.get("pairingRejectedWithError") {
        return Err(rejection_error(rejected));
    }
    let encoded = event
        .pointer("/pairingData/_0/data")
        .and_then(|value| value.as_str())
        .ok_or_else(|| IdeviceError::Quic(format!("pairing response has no data: {event}")))?;
    b64_decode(encoded)
}

fn rejection_error(rejected: &serde_json::Value) -> IdeviceError {
    let message = rejected
        .pointer("/wrappedError/userInfo/NSLocalizedDescription")
        .and_then(|value| value.as_str())
        .unwrap_or("pairing rejected");
    IdeviceError::Quic(format!("pairing rejected: {message}"))
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
    use std::time::Duration;

    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn pairing_record_roundtrips_through_plist() {
        let record = PairingRecord::generate("host-identifier");
        let restored = PairingRecord::from_plist(&record.to_plist()).unwrap();
        assert_eq!(restored.identifier, record.identifier);
        assert_eq!(restored.public_key, record.public_key);
        assert_eq!(restored.private_key, record.private_key);
        assert_eq!(restored.remote_unlock_host_key, None);

        let mut record = record;
        record.remote_unlock_host_key = Some("host-key".to_string());
        let restored = PairingRecord::from_plist(&record.to_plist()).unwrap();
        assert_eq!(restored.remote_unlock_host_key.as_deref(), Some("host-key"));
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
        assert_eq!(session.encryption_key().unwrap().len(), 32);
        let identity = QuicIdentity::generate().unwrap();
        let port = session.create_quic_listener(&identity).await.unwrap();
        assert_eq!(port, server.await.unwrap());
    }

    #[tokio::test]
    async fn pair_setup_after_consent_opens_quic_listener() {
        run_setup(true, Some("unlock-key")).await;
    }

    #[tokio::test]
    async fn pair_setup_without_consent_ignores_unlock_error() {
        run_setup(false, None).await;
    }

    async fn run_setup(wait_for_consent: bool, unlock_key: Option<&str>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let unlock = unlock_key.map(str::to_string);
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            serve_setup(socket, wait_for_consent, unlock).await
        });

        let mut options = PairSetupOptions::new("host-identifier");
        options.hostname = "test-host".to_string();
        let (mut session, record) = tokio::time::timeout(
            Duration::from_secs(3),
            RemotePairingSession::pair(addr, &options),
        )
        .await
        .expect("pair_setup timed out")
        .unwrap();
        assert_eq!(record.identifier, "host-identifier");
        assert_eq!(session.encryption_key().unwrap().len(), 64);
        assert_eq!(record.remote_unlock_host_key.as_deref(), unlock_key);
        let identity = QuicIdentity::generate().unwrap();
        let port = session.create_quic_listener(&identity).await.unwrap();
        assert_eq!(port, server.await.unwrap());
    }

    async fn serve_setup(
        mut socket: tokio::net::TcpStream,
        wait_for_consent: bool,
        unlock_key: Option<String>,
    ) -> u16 {
        reply_handshake(&mut socket).await;
        if wait_for_consent {
            reject_verify_msg02(&mut socket).await;
        } else {
            reject_verify_msg03(&mut socket).await;
        }

        let consent = read_frame(&mut socket).await;
        let payload = pairing_payload(&consent);
        assert_eq!(payload["kind"], "setupManualPairing");
        assert_eq!(payload["startNewSession"], true);
        assert_eq!(payload["sendingHost"], "test-host");
        assert_eq!(
            consent["sequenceNumber"].as_u64(),
            Some(if wait_for_consent { 3 } else { 4 })
        );
        let consent_tlv = tlv::decode(&decode_pairing_data(&consent)).unwrap();
        assert_eq!(consent_tlv.get(&tlv::METHOD).unwrap(), &[0x00]);
        assert_eq!(consent_tlv.get(&tlv::STATE).unwrap(), &[0x01]);
        if wait_for_consent {
            write_frame(
                &mut socket,
                &serde_json::json!({
                    "message": {"plain": {"_0": {
                        "event": {"_0": {"awaitingUserConsent": {}}}
                    }}},
                    "originatedBy": "device",
                    "sequenceNumber": 0
                }),
            )
            .await;
        }

        let salt = [0x5a; 16];
        let server = super::super::srp::ServerSession::new("000000", &salt, &[0x11; 32]);
        write_pairing(
            &mut socket,
            &tlv::encode(&[
                (tlv::STATE, &[0x02]),
                (tlv::SALT, &salt),
                (tlv::PUBLIC_KEY, &server.public_bytes()),
            ]),
        )
        .await;

        let proof = read_frame(&mut socket).await;
        assert_eq!(pairing_payload(&proof)["kind"], "setupManualPairing");
        assert_eq!(pairing_payload(&proof)["startNewSession"], false);
        let proof_tlv = tlv::decode(&decode_pairing_data(&proof)).unwrap();
        assert_eq!(proof_tlv.get(&tlv::STATE).unwrap(), &[0x03]);
        let accepted = server
            .accept(
                proof_tlv.get(&tlv::PUBLIC_KEY).unwrap(),
                proof_tlv.get(&tlv::PROOF).unwrap(),
            )
            .unwrap();
        write_pairing(
            &mut socket,
            &tlv::encode(&[(tlv::STATE, &[0x04]), (tlv::PROOF, &accepted.proof)]),
        )
        .await;

        let saved = read_frame(&mut socket).await;
        let saved_tlv = tlv::decode(&decode_pairing_data(&saved)).unwrap();
        assert_eq!(saved_tlv.get(&tlv::STATE).unwrap(), &[0x05]);
        let setup_key = hkdf32(
            Some(b"Pair-Setup-Encrypt-Salt"),
            &accepted.key,
            b"Pair-Setup-Encrypt-Info",
        )
        .unwrap();
        let mut encrypted = saved_tlv.get(&tlv::ENCRYPTED_DATA).unwrap().clone();
        let plain = aead_decrypt(&setup_key, NONCE_PS_MSG05, &mut encrypted).unwrap();
        let inner = tlv::decode(plain).unwrap();
        assert_eq!(inner.get(&tlv::IDENTIFIER).unwrap(), b"host-identifier");
        let host_public: [u8; 32] = inner
            .get(&tlv::PUBLIC_KEY)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        let mut signed = hkdf32(
            Some(b"Pair-Setup-Controller-Sign-Salt"),
            &accepted.key,
            b"Pair-Setup-Controller-Sign-Info",
        )
        .unwrap()
        .to_vec();
        signed.extend_from_slice(b"host-identifier");
        signed.extend_from_slice(&host_public);
        let signature =
            ed25519_dalek::Signature::from_slice(inner.get(&tlv::SIGNATURE).unwrap()).unwrap();
        ed25519_dalek::VerifyingKey::from_bytes(&host_public)
            .unwrap()
            .verify_strict(&signed, &signature)
            .unwrap();
        assert_eq!(
            inner.get(&tlv::INFO).unwrap(),
            &super::super::opack::device_info("host-identifier", "test-host")
        );
        let reply = aead_encrypt(
            &setup_key,
            NONCE_PS_MSG06,
            &tlv::encode(&[(tlv::STATE, &[0x06])]),
        )
        .unwrap();
        write_pairing(
            &mut socket,
            &tlv::encode(&[(tlv::ENCRYPTED_DATA, &reply), (tlv::STATE, &[0x06])]),
        )
        .await;

        let client_key = hkdf32(None, &accepted.key, b"ClientEncrypt-main").unwrap();
        let server_key = hkdf32(None, &accepted.key, b"ServerEncrypt-main").unwrap();
        let unlock = read_encrypted(&mut socket, &client_key, 0).await;
        assert!(
            unlock["request"]["_0"]
                .get("createRemoteUnlockKey")
                .is_some()
        );
        let body = if let Some(key) = &unlock_key {
            serde_json::json!({
                "response": {"_1": {"createRemoteUnlockKey": {"hostKey": key}}}
            })
        } else {
            serde_json::json!({
                "response": {"_1": {"errorExtended": {"_0": {"userInfo": {
                    "NSLocalizedDescription": "not supported"
                }}}}}
            })
        };
        write_encrypted(&mut socket, &server_key, 0, &body).await;

        let listener = read_encrypted(&mut socket, &client_key, 1).await;
        assert_eq!(
            listener["request"]["_0"]["createListener"]["transportProtocolType"].as_str(),
            Some("quic")
        );
        write_encrypted(
            &mut socket,
            &server_key,
            1,
            &serde_json::json!({
                "response": {"_1": {"createListener": {"port": 54321}}}
            }),
        )
        .await;
        54321
    }

    async fn reject_verify_msg02(socket: &mut tokio::net::TcpStream) {
        let start = read_frame(socket).await;
        let payload = pairing_payload(&start);
        assert_eq!(payload["kind"], "verifyManualPairing");
        assert_eq!(payload["startNewSession"], true);
        assert!(payload.get("sendingHost").is_none());
        write_pairing(
            socket,
            &tlv::encode(&[(tlv::STATE, &[0x02]), (tlv::ERROR, &[0x02])]),
        )
        .await;
        let failed = read_frame(socket).await;
        assert!(
            failed["message"]["plain"]["_0"]["event"]["_0"]
                .get("pairVerifyFailed")
                .is_some()
        );
    }

    async fn reject_verify_msg03(socket: &mut tokio::net::TcpStream) {
        let start = read_frame(socket).await;
        let start_tlv = tlv::decode(&decode_pairing_data(&start)).unwrap();
        let client_public = PublicKey::from(
            <[u8; 32]>::try_from(start_tlv.get(&tlv::PUBLIC_KEY).unwrap().as_slice()).unwrap(),
        );
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&secret);
        let shared = secret.diffie_hellman(&client_public).to_bytes();
        write_pairing(
            socket,
            &tlv::encode(&[
                (tlv::STATE, &[0x02]),
                (tlv::PUBLIC_KEY, server_public.as_bytes()),
                (tlv::ENCRYPTED_DATA, b"ignored-by-client"),
            ]),
        )
        .await;

        let proof = read_frame(socket).await;
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
        assert_eq!(inner.get(&tlv::IDENTIFIER).unwrap(), b"host-identifier");
        write_pairing(
            socket,
            &tlv::encode(&[(tlv::STATE, &[0x04]), (tlv::ERROR, &[0x01])]),
        )
        .await;
        let failed = read_frame(socket).await;
        assert!(
            failed["message"]["plain"]["_0"]["event"]["_0"]
                .get("pairVerifyFailed")
                .is_some()
        );
    }

    #[tokio::test]
    async fn pair_setup_reports_user_rejection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            reply_handshake(&mut socket).await;
            reject_verify_msg02(&mut socket).await;
            let _consent = read_frame(&mut socket).await;
            write_frame(
                &mut socket,
                &serde_json::json!({
                    "message": {"plain": {"_0": {"event": {"_0": {"pairingRejectedWithError": {
                        "wrappedError": {"userInfo": {"NSLocalizedDescription": "User denied pairing"}}
                    }}}}}},
                    "originatedBy": "device",
                    "sequenceNumber": 1
                }),
            )
            .await;
        });

        let error = tokio::time::timeout(
            Duration::from_secs(3),
            RemotePairingSession::pair(addr, &PairSetupOptions::new("host-identifier")),
        )
        .await
        .expect("pair_setup timed out")
        .unwrap_err();
        assert!(error.to_string().contains("User denied pairing"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn pair_setup_stops_when_verify_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            reply_handshake(&mut socket).await;
            let start = read_frame(&mut socket).await;
            let start_tlv = tlv::decode(&decode_pairing_data(&start)).unwrap();
            let client_public = PublicKey::from(
                <[u8; 32]>::try_from(start_tlv.get(&tlv::PUBLIC_KEY).unwrap().as_slice()).unwrap(),
            );
            let secret = EphemeralSecret::random_from_rng(OsRng);
            let server_public = PublicKey::from(&secret);
            let _shared = secret.diffie_hellman(&client_public);
            write_pairing(
                &mut socket,
                &tlv::encode(&[
                    (tlv::STATE, &[0x02]),
                    (tlv::PUBLIC_KEY, server_public.as_bytes()),
                    (tlv::ENCRYPTED_DATA, b"ignored-by-client"),
                ]),
            )
            .await;
            let _proof = read_frame(&mut socket).await;
            write_pairing(&mut socket, &tlv::encode(&[(tlv::STATE, &[0x04])])).await;
        });

        let (session, record) = tokio::time::timeout(
            Duration::from_secs(3),
            RemotePairingSession::pair(addr, &PairSetupOptions::new("host-identifier")),
        )
        .await
        .expect("pair_setup timed out")
        .unwrap();
        assert_eq!(record.identifier, "host-identifier");
        assert_eq!(session.encryption_key().unwrap().len(), 32);
        assert!(record.remote_unlock_host_key.is_none());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn pair_setup_rejects_an_empty_identifier() {
        let (client, _server) = tokio::io::duplex(64);
        let mut session = RemotePairingSession::new(client, "127.0.0.1:1".parse().unwrap());
        let error = session
            .pair_setup(&PairSetupOptions::new(""))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("identifier"));
    }

    async fn reply_handshake(socket: &mut tokio::net::TcpStream) {
        let handshake = read_frame(socket).await;
        assert_eq!(handshake["sequenceNumber"].as_u64(), Some(0));
        write_frame(
            socket,
            &serde_json::json!({
                "message": {"plain": {"_0": {
                    "response": {"_1": {"handshake": {"_0": {"accepted": true}}}}
                }}},
                "originatedBy": "device",
                "sequenceNumber": 0
            }),
        )
        .await;
    }

    fn pairing_payload(message: &serde_json::Value) -> &serde_json::Value {
        &message["message"]["plain"]["_0"]["event"]["_0"]["pairingData"]["_0"]
    }

    async fn read_encrypted(
        socket: &mut tokio::net::TcpStream,
        key: &[u8; 32],
        sequence: u64,
    ) -> serde_json::Value {
        let frame = read_frame(socket).await;
        let mut ciphertext =
            b64_decode(frame["message"]["streamEncrypted"]["_0"].as_str().unwrap()).unwrap();
        let plain = aead_decrypt(key, &encrypted_nonce(sequence), &mut ciphertext).unwrap();
        serde_json::from_slice(plain).unwrap()
    }

    async fn write_encrypted(
        socket: &mut tokio::net::TcpStream,
        key: &[u8; 32],
        sequence: u64,
        body: &serde_json::Value,
    ) {
        let encrypted = aead_encrypt(
            key,
            &encrypted_nonce(sequence),
            &serde_json::to_vec(body).unwrap(),
        )
        .unwrap();
        write_frame(
            socket,
            &serde_json::json!({
                "message": {"streamEncrypted": {"_0": b64(&encrypted)}},
                "originatedBy": "device",
                "sequenceNumber": sequence
            }),
        )
        .await;
    }
}
