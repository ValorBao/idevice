//! TLV8 codec used by Remote Pairing.
//!
//! Values longer than 255 bytes are split across consecutive entries of the
//! same type. Decoding concatenates those entries.

use std::collections::BTreeMap;

use crate::IdeviceError;

pub const METHOD: u8 = 0x00;
pub const IDENTIFIER: u8 = 0x01;
pub const SALT: u8 = 0x02;
pub const PUBLIC_KEY: u8 = 0x03;
pub const PROOF: u8 = 0x04;
pub const ENCRYPTED_DATA: u8 = 0x05;
pub const STATE: u8 = 0x06;
pub const ERROR: u8 = 0x07;
pub const SIGNATURE: u8 = 0x0A;
pub const INFO: u8 = 0x11;

/// Encodes TLV8 entries, splitting any value longer than 255 bytes.
pub fn encode(entries: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (kind, value) in entries {
        if value.is_empty() {
            out.push(*kind);
            out.push(0);
            continue;
        }
        for chunk in value.chunks(255) {
            out.push(*kind);
            out.push(chunk.len() as u8);
            out.extend_from_slice(chunk);
        }
    }
    out
}

/// Decodes TLV8 bytes, concatenating adjacent entries of the same type.
pub fn decode(bytes: &[u8]) -> Result<BTreeMap<u8, Vec<u8>>, IdeviceError> {
    let mut out: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes.len() - index < 2 {
            return Err(IdeviceError::Quic(
                "truncated remote pairing tlv8".to_string(),
            ));
        }
        let kind = bytes[index];
        let len = bytes[index + 1] as usize;
        index += 2;
        if bytes.len() - index < len {
            return Err(IdeviceError::Quic(
                "truncated remote pairing tlv8 value".to_string(),
            ));
        }
        out.entry(kind)
            .or_default()
            .extend_from_slice(&bytes[index..index + len]);
        index += len;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_and_rejoins_long_values() {
        let long = vec![0xAB; 300];
        let encoded = encode(&[(PUBLIC_KEY, &long), (STATE, &[0x01])]);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.get(&PUBLIC_KEY).unwrap(), &long);
        assert_eq!(decoded.get(&STATE).unwrap(), &[0x01]);
    }
}
