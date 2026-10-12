//! RSA identity presented to an iOS Remote Pairing QUIC listener.
//!
//! The device only accepts a connection whose client certificate uses the same
//! public key that was sent in the `createListener` request.

use std::str::FromStr;

use base64::Engine;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1v15::SigningKey,
    pkcs8::{EncodePrivateKey, EncodePublicKey, SubjectPublicKeyInfo},
};
use sha2::Sha256;
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    der::Encode,
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};

use crate::IdeviceError;

/// Key material for one Remote Pairing QUIC listener.
///
/// Generate this before asking the device to create a listener, send
/// [`Self::listener_request`] inside the encrypted RPPairing session, then pass
/// the same identity to [`super::QuicTunnel::connect`].
#[derive(Clone)]
pub struct QuicIdentity {
    public_key_der: Vec<u8>,
    public_key_base64: String,
    certificate_der: Vec<u8>,
    private_key_pkcs8: Vec<u8>,
}

impl std::fmt::Debug for QuicIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicIdentity")
            .field("public_key_base64", &self.public_key_base64)
            .finish_non_exhaustive()
    }
}

impl QuicIdentity {
    /// Generates a fresh 2048-bit RSA key and a one-year self-signed certificate.
    pub fn generate() -> Result<Self, IdeviceError> {
        let mut rng = rsa::rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| IdeviceError::InternalError(format!("rsa key generation failed: {e}")))?;
        let public_key = RsaPublicKey::from(&private_key);

        let public_key_doc = public_key
            .to_public_key_der()
            .map_err(|e| IdeviceError::InternalError(format!("spki encode failed: {e}")))?;
        let public_key_der = public_key_doc.as_bytes().to_vec();
        let public_key_base64 = base64::engine::general_purpose::STANDARD.encode(&public_key_der);

        let certificate_der = self_signed_leaf(&private_key, &public_key)?;
        let private_doc = private_key
            .to_pkcs8_der()
            .map_err(|e| IdeviceError::InternalError(format!("pkcs8 encode failed: {e}")))?;

        Ok(Self {
            public_key_der,
            public_key_base64,
            certificate_der,
            private_key_pkcs8: private_doc.as_bytes().to_vec(),
        })
    }

    /// SubjectPublicKeyInfo bytes, which is the `key` field of `createListener`.
    pub fn public_key_der(&self) -> &[u8] {
        &self.public_key_der
    }

    /// Standard base64 of [`Self::public_key_der`].
    pub fn public_key_base64(&self) -> &str {
        &self.public_key_base64
    }

    /// RPPairing `createListener` request for a QUIC tunnel bound to this key.
    ///
    /// Send this object as the encrypted request body. The device responds with
    /// the UDP port to pass to [`super::QuicTunnel::connect`].
    pub fn listener_request(&self) -> serde_json::Value {
        serde_json::json!({
            "request": {
                "_0": {
                    "createListener": {
                        "key": self.public_key_base64,
                        "peerConnectionsInfo": [{
                            "owningPID": std::process::id(),
                            "owningProcessName": "CoreDeviceService"
                        }],
                        "transportProtocolType": "quic"
                    }
                }
            }
        })
    }

    pub(crate) fn rustls_certificate(&self) -> rustls::pki_types::CertificateDer<'static> {
        rustls::pki_types::CertificateDer::from(self.certificate_der.clone())
    }

    pub(crate) fn rustls_key(&self) -> rustls::pki_types::PrivateKeyDer<'static> {
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            self.private_key_pkcs8.clone(),
        ))
    }
}

fn self_signed_leaf(
    private_key: &RsaPrivateKey,
    public_key: &RsaPublicKey,
) -> Result<Vec<u8>, IdeviceError> {
    let name = Name::from_str("CN=RemotePairing")
        .map_err(|e| IdeviceError::InternalError(format!("certificate name: {e}")))?;
    let validity = Validity::from_now(std::time::Duration::from_secs(365 * 24 * 60 * 60))
        .map_err(|e| IdeviceError::InternalError(format!("certificate validity: {e}")))?;
    let signing_key = SigningKey::<Sha256>::new(private_key.clone());
    let spki = SubjectPublicKeyInfo::from_key(public_key.clone())
        .map_err(|e| IdeviceError::InternalError(format!("certificate spki: {e}")))?;
    let cert = CertificateBuilder::new(
        Profile::Leaf {
            issuer: name.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        SerialNumber::new(&[1, 2, 3, 4])
            .map_err(|e| IdeviceError::InternalError(format!("certificate serial: {e}")))?,
        validity,
        name,
        spki,
        &signing_key,
    )
    .map_err(|e| IdeviceError::InternalError(format!("certificate builder: {e}")))?;
    let cert = cert
        .build()
        .map_err(|e| IdeviceError::InternalError(format!("certificate sign: {e}")))?;
    cert.to_der()
        .map_err(|e| IdeviceError::InternalError(format!("certificate der: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_request_carries_spki_and_quic_transport() {
        let identity = QuicIdentity::generate().expect("identity");
        let request = identity.listener_request();
        let listener = &request["request"]["_0"]["createListener"];
        assert_eq!(listener["transportProtocolType"].as_str(), Some("quic"));
        assert_eq!(listener["key"].as_str(), Some(identity.public_key_base64()));
        let der = base64::engine::general_purpose::STANDARD
            .decode(identity.public_key_base64())
            .expect("base64");
        assert_eq!(der, identity.public_key_der());
        assert_eq!(der[0], 0x30);
        assert!(!identity.certificate_der.is_empty());
        assert!(!identity.private_key_pkcs8.is_empty());
    }
}
