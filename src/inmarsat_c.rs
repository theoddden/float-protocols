//! Inmarsat C protocol parsing and encoding
//!
//! Inmarsat C is a teletype format (128 bytes max) used for maritime communication.

use bytes::Bytes;

#[derive(Debug, Clone)]
pub struct InmarsatCMessage {
    pub message_number: u16,
    pub destination_id: String,
    pub source_id: String,
    pub payload: Bytes,
}

impl InmarsatCMessage {
    /// Parse Inmarsat C message from bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }

        // Inmarsat C format (simplified):
        // Bytes 0-1: Message number (big-endian)
        // Bytes 2-5: Destination ID (4 bytes)
        // Bytes 6-9: Source ID (4 bytes)
        // Bytes 10-127: Payload

        let message_number = u16::from_be_bytes([data[0], data[1]]);
        let destination_id = format!(
            "{:02x}{:02x}{:02x}{:02x}",
            data[2], data[3], data[4], data[5]
        );
        let source_id = format!(
            "{:02x}{:02x}{:02x}{:02x}",
            data[6], data[7], data[8], data[9]
        );
        let payload = Bytes::copy_from_slice(&data[10..]);

        Some(Self {
            message_number,
            destination_id,
            source_id,
            payload,
        })
    }

    /// Encode Inmarsat C message to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = vec![0u8; 128]; // Inmarsat C max size

        // Message number (bytes 0-1)
        buffer[0..2].copy_from_slice(&self.message_number.to_be_bytes());

        // Destination ID (bytes 2-5)
        let dest_bytes = hex::decode(&self.destination_id).unwrap_or_else(|_| vec![0u8; 4]);
        buffer[2..6].copy_from_slice(&dest_bytes[..4.min(dest_bytes.len())]);

        // Source ID (bytes 6-9)
        let src_bytes = hex::decode(&self.source_id).unwrap_or_else(|_| vec![0u8; 4]);
        buffer[6..10].copy_from_slice(&src_bytes[..4.min(src_bytes.len())]);

        // Payload (bytes 10-127)
        let payload_len = self.payload.len().min(118);
        buffer[10..10 + payload_len].copy_from_slice(&self.payload[..payload_len]);

        buffer.truncate(10 + payload_len);
        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inmarsat_c_parse() {
        let mut data = vec![0u8; 20];
        data[0..2].copy_from_slice(&1234u16.to_be_bytes());
        data[10] = b'H';
        data[11] = b'e';
        data[12] = b'l';
        data[13] = b'l';
        data[14] = b'o';

        let msg = InmarsatCMessage::parse(&data);
        assert!(msg.is_some());
        assert_eq!(msg.unwrap().message_number, 1234);
    }

    #[test]
    fn test_inmarsat_c_parse_too_short() {
        let data = b"short";
        let msg = InmarsatCMessage::parse(data);
        assert!(msg.is_none());
    }

    #[test]
    fn test_inmarsat_c_encode() {
        let msg = InmarsatCMessage {
            message_number: 1234,
            destination_id: "01020304".to_string(),
            source_id: "05060708".to_string(),
            payload: Bytes::from("Hello"),
        };

        let encoded = msg.encode();
        assert!(encoded.len() >= 10);
        assert_eq!(u16::from_be_bytes([encoded[0], encoded[1]]), 1234);
    }
}
