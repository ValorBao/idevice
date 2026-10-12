//! SRP-3072 client used by Remote Pairing pair-setup.
//!
//! The arithmetic follows srptools 1.0.1, which is what pymobiledevice3 sends
//! to the device: SHA-512, RFC 5054 group 3072 with generator 5, username
//! `Pair-Setup` inside `x`, and unpadded big-endian integers everywhere except
//! `k = H(N | PAD(g))` and `u = H(PAD(A) | PAD(B))`. The session key is
//! `K = H(S)` (64 bytes), not `H(PAD(S))`.

use std::sync::OnceLock;

use num_bigint::BigUint;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha512};

use crate::IdeviceError;

const USERNAME: &str = "Pair-Setup";
const PRIME_3072: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

struct Group {
    prime: BigUint,
    generator: BigUint,
    multiplier: BigUint,
    pad_len: usize,
}

/// Client messages for one SRP handshake.
pub(crate) struct ClientSession {
    /// Unpadded `A = g^a mod N`.
    pub public: Vec<u8>,
    /// Client proof `M1`.
    pub proof: Vec<u8>,
    /// Expected server proof `M2`.
    pub server_proof: Vec<u8>,
    /// Session key `K = H(S)`, 64 bytes.
    pub key: Vec<u8>,
}

/// Starts an SRP-3072 client session for `password` (the device PIN).
pub(crate) fn client_session(
    password: &str,
    salt: &[u8],
    server_public: &[u8],
) -> Result<ClientSession, IdeviceError> {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    if secret.iter().all(|byte| *byte == 0) {
        secret[31] = 1;
    }
    client_session_with_secret(password, salt, server_public, &secret)
}

pub(crate) fn client_session_with_secret(
    password: &str,
    salt: &[u8],
    server_public: &[u8],
    secret: &[u8],
) -> Result<ClientSession, IdeviceError> {
    let group = group();
    let server = BigUint::from_bytes_be(server_public);
    if (&server % &group.prime) == BigUint::from(0u8) {
        return Err(IdeviceError::Quic(
            "SRP server public key is 0 mod N".to_string(),
        ));
    }
    let client_private = BigUint::from_bytes_be(secret);
    if client_private == BigUint::from(0u8) {
        return Err(IdeviceError::Quic("SRP client secret is 0".to_string()));
    }
    let x = password_hash(salt, password);
    let verifier = group.generator.modpow(&x, &group.prime);
    let client_public = group.generator.modpow(&client_private, &group.prime);
    let u = scrambling(&client_public, &server, group.pad_len);
    let premaster = client_premaster(group, &client_private, &server, &verifier, &u, &x);
    let key = sha512(&minimal(&premaster)).to_vec();
    let proof = proof_m1(&client_public, &server, salt, &key);
    let server_proof = proof_m2(&client_public, &proof, &key);
    Ok(ClientSession {
        public: minimal(&client_public),
        proof,
        server_proof,
        key,
    })
}

#[cfg(test)]
pub(crate) struct ServerSession {
    server_private: BigUint,
    server_public: BigUint,
    verifier: BigUint,
    salt: Vec<u8>,
}

#[cfg(test)]
pub(crate) struct Accepted {
    pub proof: Vec<u8>,
    pub key: Vec<u8>,
}

#[cfg(test)]
impl ServerSession {
    pub(crate) fn new(password: &str, salt: &[u8], secret: &[u8]) -> Self {
        let group = group();
        let x = password_hash(salt, password);
        let verifier = group.generator.modpow(&x, &group.prime);
        let server_private = BigUint::from_bytes_be(secret);
        let server_public = ((&group.multiplier * &verifier)
            + group.generator.modpow(&server_private, &group.prime))
            % &group.prime;
        Self {
            server_private,
            server_public,
            verifier,
            salt: salt.to_vec(),
        }
    }

    pub(crate) fn public_bytes(&self) -> Vec<u8> {
        minimal(&self.server_public)
    }

    pub(crate) fn accept(
        &self,
        client_public: &[u8],
        client_proof: &[u8],
    ) -> Result<Accepted, IdeviceError> {
        let group = group();
        let client = BigUint::from_bytes_be(client_public);
        if (&client % &group.prime) == BigUint::from(0u8) {
            return Err(IdeviceError::Quic(
                "SRP client public key is 0 mod N".to_string(),
            ));
        }
        let u = scrambling(&client, &self.server_public, group.pad_len);
        let vu = self.verifier.modpow(&u, &group.prime);
        let base = (&client * &vu) % &group.prime;
        let premaster = base.modpow(&self.server_private, &group.prime);
        let key = sha512(&minimal(&premaster)).to_vec();
        let proof = proof_m1(&client, &self.server_public, &self.salt, &key);
        if proof != client_proof {
            return Err(IdeviceError::Quic(
                "SRP client proof did not match".to_string(),
            ));
        }
        Ok(Accepted {
            proof: proof_m2(&client, &proof, &key),
            key,
        })
    }
}

fn group() -> &'static Group {
    static GROUP: OnceLock<Group> = OnceLock::new();
    GROUP.get_or_init(|| {
        let prime = BigUint::from_bytes_be(&decode_hex(PRIME_3072));
        let generator = BigUint::from(5u8);
        let pad_len = minimal(&prime).len();
        let mut multiplier_input = minimal(&prime);
        multiplier_input.extend_from_slice(&pad_int(&generator, pad_len));
        let multiplier = BigUint::from_bytes_be(&sha512(&multiplier_input));
        Group {
            prime,
            generator,
            multiplier,
            pad_len,
        }
    })
}

fn password_hash(salt: &[u8], password: &str) -> BigUint {
    let mut identity = b"Pair-Setup:".to_vec();
    identity.extend_from_slice(password.as_bytes());
    let inner = sha512(&identity);
    let mut outer = Vec::with_capacity(salt.len() + inner.len());
    outer.extend_from_slice(salt);
    outer.extend_from_slice(&inner);
    BigUint::from_bytes_be(&sha512(&outer))
}

fn scrambling(client_public: &BigUint, server_public: &BigUint, pad_len: usize) -> BigUint {
    let mut input = pad_int(client_public, pad_len);
    input.extend_from_slice(&pad_int(server_public, pad_len));
    BigUint::from_bytes_be(&sha512(&input))
}

fn client_premaster(
    group: &Group,
    client_private: &BigUint,
    server_public: &BigUint,
    verifier: &BigUint,
    u: &BigUint,
    x: &BigUint,
) -> BigUint {
    let kv = (&group.multiplier * verifier) % &group.prime;
    let b_mod = server_public % &group.prime;
    let base = if b_mod >= kv {
        b_mod - kv
    } else {
        &group.prime - (kv - b_mod)
    };
    let exponent = client_private + &(u * x);
    base.modpow(&exponent, &group.prime)
}

fn proof_m1(client_public: &BigUint, server_public: &BigUint, salt: &[u8], key: &[u8]) -> Vec<u8> {
    let group = group();
    let prime_hash = sha512(&minimal(&group.prime));
    let generator_hash = sha512(&minimal(&group.generator));
    let mixed = strip_zeros(&xor_bytes(&prime_hash, &generator_hash));
    let user = minimal(&BigUint::from_bytes_be(&sha512(USERNAME.as_bytes())));
    let mut input = Vec::new();
    input.extend_from_slice(&mixed);
    input.extend_from_slice(&user);
    input.extend_from_slice(salt);
    input.extend_from_slice(&minimal(client_public));
    input.extend_from_slice(&minimal(server_public));
    input.extend_from_slice(key);
    sha512(&input).to_vec()
}

fn proof_m2(client_public: &BigUint, client_proof: &[u8], key: &[u8]) -> Vec<u8> {
    let mut input = minimal(client_public);
    input.extend_from_slice(client_proof);
    input.extend_from_slice(key);
    sha512(&input).to_vec()
}

fn pad_int(value: &BigUint, len: usize) -> Vec<u8> {
    let raw = minimal(value);
    if raw.len() >= len {
        return raw;
    }
    let mut padded = vec![0u8; len - raw.len()];
    padded.extend_from_slice(&raw);
    padded
}

fn minimal(value: &BigUint) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    if bytes.is_empty() { vec![0] } else { bytes }
}

fn strip_zeros(bytes: &[u8]) -> Vec<u8> {
    match bytes.iter().position(|byte| *byte != 0) {
        Some(index) => bytes[index..].to_vec(),
        None => vec![0],
    }
}

fn xor_bytes(left: &[u8; 64], right: &[u8; 64]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for index in 0..64 {
        out[index] = left[index] ^ right[index];
    }
    out
}

fn sha512(data: &[u8]) -> [u8; 64] {
    Sha512::digest(data).into()
}

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("prime hex"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_strips_leading_zeros() {
        assert_eq!(strip_zeros(&[0, 0, 1, 0]), &[1, 0]);
        assert_eq!(strip_zeros(&[0, 0]), &[0]);
        assert_eq!(strip_zeros(&[2, 0]), &[2, 0]);
    }

    #[test]
    fn matches_srptools_vector() {
        let salt = hex("00112233445566778899aabbccddeeff");
        let server = ServerSession::new("000000", &salt, &[0x11; 32]);
        let client =
            client_session_with_secret("000000", &salt, &server.public_bytes(), &[0x22; 32])
                .unwrap();
        assert_eq!(
            hex_encode(&server.public_bytes()),
            "5d47473e4fc3562b093b57056dee4e4ef86dd47dbbd12a941fca34e937a5becca78af5609523faa4688b3ebed641afccf225112c296d5377c2eddce124f1e34304522a4f91208416fa1a674a1daa4e60aa081ce91f3093bd7a921dcb2514c483266340cc1cfa677a0bcb913218911a582077b272a4dc4230b9385a964f10d3828cba124d67ece339f475f305e68bb2c796d03e73e8451fb24119bb2378c253bb576a3c9502d433b425fa663a97cb10d642d72ff90f5b1014d2238c94a29bbf97310507e47cef384ee31d4533f07f2d0a02280cdd61d544995ec063fd4cc12ca91792172dee9d732a826d8e3f3f068abfcdcb0f22ecd75b2b2e139c974b0b831fb3256c5ec5467bc75605490cfd2f9e8ee145e8e48e2007234ea54770654016f5163f7f0823bec9d97ef279059506e1204d7b2b66ddc9dda3a899e3e2aca5d67d2017c4ad9e4413be5061466ec16299f9d1d8e27ebecc8b93735832ae16d192104cbaa32da4ced4c6427a498f56f0503eefd3cc7461c395610df94607037213b9"
        );
        assert_eq!(
            hex_encode(&client.public),
            "81093727015ff43ece825f4417676f6b9296c8e61f98009a5c4d2045561198c92f0151afa817ca3737da3e71611a5f84d80074adae5c40c6565d99d030705f4daf4a08bed17de15b5f7109e1d431a599d2c305f0c305a1a4c87b9d95f981553a19cb21d461835a27f5e0455f1fe865633119ae86aca1db4ee95d6c411c8e84a23952b595f966ce4ef022ef2fe825caf91c456bc760aaa10c652f46f7eea471ae835b50c564219d57d1acdfb70fb59d55c0a6beb33672675cc1ba4fd88c9aa07e83d66fb9f19104fa251e3a6341f59103da79d27f4b9bdfcff286f9e3cb6ce50d8deff275640515e0b1c8cc9f2d78fae8239ade555f240f28942cb8fe8d319777cf1484d6e34930aaf699ff67e31530981488b05612178ab4954ae047ffde2ce9806f30f0b260225e5270449ea8614ba3b03dde9a452ce73d78c03656d66979b03152d56f77295e91a91921ac6add385bb2e7ee836171acb9058c1d6501509bfdff3c9d24bc4d6db18497ef66d7dbbbd6189f74f5ac4a83130659ee3e89f89dea"
        );
        assert_eq!(
            hex_encode(&client.key),
            "32b49011d55b9eb72fd9659e76d67c2c8ef8f7b6f467e05719297ab22cf004d13e17f0ced4883fa9c45ee4f625dbcc1dded5ca6d263f5e313e1fc916f074111c"
        );
        assert_eq!(
            hex_encode(&client.proof),
            "516742b60e9f9d45b15a51d7f0e73b25aece15ec3bfb39dc4257351b446fe3da483b8bf657a42368fb16e62433f856dd3447e4593dc91beed68a80bd2a1c33a2"
        );
        assert_eq!(
            hex_encode(&client.server_proof),
            "da429100e1ce20c21377c39e4bf21ac284d73a452bee3cf1b3a3d451eb74d560000a3e429f275aeec65f9789be324719f47d07d0f98cfe04cb1f16265f4993ed"
        );
        let accepted = server.accept(&client.public, &client.proof).unwrap();
        assert_eq!(accepted.key, client.key);
        assert_eq!(accepted.proof, client.server_proof);
    }

    #[test]
    fn agrees_on_random_secrets() {
        let mut salt = [0u8; 16];
        let mut client_secret = [0u8; 32];
        let mut server_secret = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut client_secret);
        OsRng.fill_bytes(&mut server_secret);
        client_secret[0] |= 1;
        server_secret[0] |= 1;
        let server = ServerSession::new("000000", &salt, &server_secret);
        let client =
            client_session_with_secret("000000", &salt, &server.public_bytes(), &client_secret)
                .unwrap();
        let accepted = server.accept(&client.public, &client.proof).unwrap();
        assert_eq!(accepted.key, client.key);
        assert_eq!(accepted.proof, client.server_proof);
        assert_eq!(client.key.len(), 64);
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
