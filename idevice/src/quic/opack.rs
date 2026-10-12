//! Device-info blob sent inside pair-setup.
//!
//! The dictionary matches the one pymobiledevice3 encodes with `opack2`. The
//! device does not check these placeholder values; it only needs a well-formed
//! OPack object.

/// OPack dictionary placed in the pair-setup Info TLV.
pub(crate) fn device_info(identifier: &str, hostname: &str) -> Vec<u8> {
    // pymobiledevice3's fixed placeholders. `-` is 0x2d and `{` is 0x7b.
    let alt_irk: [u8; 16] = [
        0xe9, 0xe8, 0x2d, 0xc0, 0x6a, 0x49, 0x79, 0x6b, 0x56, 0x6f, 0x54, 0x00, 0x19, 0xb1, 0xc7,
        0x7b,
    ];
    let mac: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    let mut out = Vec::new();
    // Seven entries: marker 0xE0 + count.
    out.push(0xE7);
    push_str(&mut out, "altIRK");
    push_bytes(&mut out, &alt_irk);
    push_str(&mut out, "btAddr");
    push_str(&mut out, "11:22:33:44:55:66");
    push_str(&mut out, "mac");
    push_bytes(&mut out, &mac);
    push_str(&mut out, "remotepairing_serial_number");
    push_str(&mut out, "AAAAAAAAAAAA");
    push_str(&mut out, "accountID");
    push_str(&mut out, identifier);
    push_str(&mut out, "model");
    push_str(&mut out, "computer-model");
    push_str(&mut out, "name");
    push_str(&mut out, hostname);
    out
}

fn push_str(out: &mut Vec<u8>, text: &str) {
    let bytes = text.as_bytes();
    match bytes.len() {
        0..=31 => out.push(0x40 + bytes.len() as u8),
        32..=255 => {
            out.push(0x61);
            out.push(bytes.len() as u8);
        }
        len if len <= u16::MAX as usize => {
            out.push(0x62);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        len => {
            out.push(0x63);
            out.extend_from_slice(&(len as u32).to_be_bytes());
        }
    }
    out.extend_from_slice(bytes);
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    match bytes.len() {
        0..=31 => out.push(0x70 + bytes.len() as u8),
        32..=255 => {
            out.push(0x91);
            out.push(bytes.len() as u8);
        }
        len if len <= u16::MAX as usize => {
            out.push(0x92);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        len => {
            out.push(0x93);
            out.extend_from_slice(&(len as u32).to_be_bytes());
        }
    }
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_opack2_device_info() {
        let encoded = device_info("host-identifier", "test-host");
        assert_eq!(
            encoded,
            hex(
                "e746616c7449524b80e9e82dc06a49796b566f540019b1c77b466274416464725131313a32323a33333a34343a35353a3636436d6163761122334455665b72656d6f746570616972696e675f73657269616c5f6e756d6265724c414141414141414141414141496163636f756e7449444f686f73742d6964656e746966696572456d6f64656c4e636f6d70757465722d6d6f64656c446e616d6549746573742d686f7374"
            )
        );
    }

    #[test]
    fn long_account_id_uses_counted_string() {
        let identifier = "12345678-1234-1234-1234-123456789abc";
        let encoded = device_info(identifier, "h");
        let key = b"accountID";
        let index = encoded
            .windows(key.len())
            .position(|window| window == key)
            .unwrap();
        assert_eq!(encoded[index + key.len()], 0x61);
        assert_eq!(encoded[index + key.len() + 1] as usize, identifier.len());
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }
}
