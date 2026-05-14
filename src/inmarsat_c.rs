//! Inmarsat C protocol parsing and encoding
//!
//! Inmarsat C is a teletype format (128 bytes max) used for maritime communication.

use bytes::Bytes;
use crc::{Crc, CRC_16_IBM_3740};

const MAGIC_NUMBER: u32 = 0x494E4D01; // "INM\x01"
const CRC: Crc<u16> = Crc::<u16>::new(&CRC_16_IBM_3740);

#[derive(Debug)]
pub enum ParseError {
    InvalidMagicNumber { found: u32, expected: u32 },
    ChecksumMismatch { expected: u16, found: u16 },
    InvalidLength { min: usize, found: usize },
    InvalidDestinationId { value: String },
    InvalidSourceId { value: String },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::InvalidMagicNumber { found, expected } => {
                write!(
                    f,
                    "Invalid magic number: found 0x{:08x}, expected 0x{:08x}",
                    found, expected
                )
            }
            ParseError::ChecksumMismatch { expected, found } => {
                write!(
                    f,
                    "Checksum mismatch: expected 0x{:04x}, found 0x{:04x}",
                    expected, found
                )
            }
            ParseError::InvalidLength { min, found } => {
                write!(f, "Invalid length: minimum {}, found {}", min, found)
            }
            ParseError::InvalidDestinationId { value } => {
                write!(f, "Invalid destination ID: {}", value)
            }
            ParseError::InvalidSourceId { value } => {
                write!(f, "Invalid source ID: {}", value)
            }
        }
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug, Clone)]
pub struct InmarsatCMessage {
    pub message_number: u16,
    pub destination_id: String,
    pub source_id: String,
    pub payload: Bytes,
}

impl InmarsatCMessage {
    fn compute_checksum(data: &[u8]) -> u16 {
        CRC.checksum(data)
    }

    /// Parse Inmarsat C message from bytes
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        // Minimum length: magic (4) + message_number (2) + dest_id (4) + source_id (4) + checksum (2) = 16 bytes
        if data.len() < 16 {
            return Err(ParseError::InvalidLength {
                min: 16,
                found: data.len(),
            });
        }

        // Validate magic number (bytes 0-3)
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != MAGIC_NUMBER {
            return Err(ParseError::InvalidMagicNumber {
                found: magic,
                expected: MAGIC_NUMBER,
            });
        }

        // Validate checksum (last 2 bytes)
        let payload_len = data.len() - 2;
        let computed_checksum = Self::compute_checksum(&data[..payload_len]);
        let stored_checksum = u16::from_be_bytes([data[payload_len], data[payload_len + 1]]);

        if computed_checksum != stored_checksum {
            return Err(ParseError::ChecksumMismatch {
                expected: computed_checksum,
                found: stored_checksum,
            });
        }

        // Parse message (excluding checksum bytes)
        Self::parse_inner(&data[..payload_len])
    }

    fn parse_inner(data: &[u8]) -> Result<Self, ParseError> {
        // Inmarsat C format:
        // Bytes 0-3: Magic number (already validated)
        // Bytes 4-5: Message number (big-endian)
        // Bytes 6-9: Destination ID (4 bytes)
        // Bytes 10-13: Source ID (4 bytes)
        // Bytes 14-127: Payload

        let message_number = u16::from_be_bytes([data[4], data[5]]);

        let destination_id = format!(
            "{:02x}{:02x}{:02x}{:02x}",
            data[6], data[7], data[8], data[9]
        );

        // Validate destination ID is valid hex
        if hex::decode(&destination_id).is_err() {
            return Err(ParseError::InvalidDestinationId {
                value: destination_id,
            });
        }

        let source_id = format!(
            "{:02x}{:02x}{:02x}{:02x}",
            data[10], data[11], data[12], data[13]
        );

        // Validate source ID is valid hex
        if hex::decode(&source_id).is_err() {
            return Err(ParseError::InvalidSourceId { value: source_id });
        }

        let payload = if data.len() > 14 {
            Bytes::copy_from_slice(&data[14..])
        } else {
            Bytes::new()
        };

        Ok(Self {
            message_number,
            destination_id,
            source_id,
            payload,
        })
    }

    /// Encode Inmarsat C message to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = vec![0u8; 128]; // Inmarsat C max size

        // Magic number (bytes 0-3)
        buffer[0..4].copy_from_slice(&MAGIC_NUMBER.to_be_bytes());

        // Message number (bytes 4-5)
        buffer[4..6].copy_from_slice(&self.message_number.to_be_bytes());

        // Destination ID (bytes 6-9)
        let dest_bytes = hex::decode(&self.destination_id).unwrap_or_else(|_| vec![0u8; 4]);
        buffer[6..10].copy_from_slice(&dest_bytes[..4.min(dest_bytes.len())]);

        // Source ID (bytes 10-13)
        let src_bytes = hex::decode(&self.source_id).unwrap_or_else(|_| vec![0u8; 4]);
        buffer[10..14].copy_from_slice(&src_bytes[..4.min(src_bytes.len())]);

        // Payload (bytes 14-127)
        let payload_len = self.payload.len().min(114);
        buffer[14..14 + payload_len].copy_from_slice(&self.payload[..payload_len]);

        let data_len = 14 + payload_len;
        buffer.truncate(data_len);

        // Compute and append checksum
        let checksum = Self::compute_checksum(&buffer[..data_len]);
        buffer.extend_from_slice(&checksum.to_be_bytes());

        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inmarsat_c_parse() {
        let mut data = vec![0u8; 21];
        // Magic number
        data[0..4].copy_from_slice(&MAGIC_NUMBER.to_be_bytes());
        // Message number
        data[4..6].copy_from_slice(&1234u16.to_be_bytes());
        // Destination ID
        data[6..10].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        // Source ID
        data[10..14].copy_from_slice(&[0x05, 0x06, 0x07, 0x08]);
        // Payload
        data[14] = b'H';
        data[15] = b'e';
        data[16] = b'l';
        data[17] = b'l';
        data[18] = b'o';

        // Compute checksum
        let checksum = Crc::<u16>::new(&CRC_16_IBM_3740).checksum(&data[..19]);
        data[19..21].copy_from_slice(&checksum.to_be_bytes());

        let msg = InmarsatCMessage::parse(&data);
        assert!(msg.is_ok());
        assert_eq!(msg.unwrap().message_number, 1234);
    }

    #[test]
    fn test_inmarsat_c_parse_invalid_magic() {
        let mut data = vec![0u8; 20];
        // Wrong magic number
        data[0..4].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        // Rest of valid data
        data[4..6].copy_from_slice(&1234u16.to_be_bytes());
        data[6..10].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        data[10..14].copy_from_slice(&[0x05, 0x06, 0x07, 0x08]);

        let msg = InmarsatCMessage::parse(&data);
        assert!(msg.is_err());
        assert!(matches!(
            msg.unwrap_err(),
            ParseError::InvalidMagicNumber { .. }
        ));
    }

    #[test]
    fn test_inmarsat_c_parse_too_short() {
        let data = b"short";
        let msg = InmarsatCMessage::parse(data);
        assert!(msg.is_err());
        assert!(matches!(msg.unwrap_err(), ParseError::InvalidLength { .. }));
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
        assert!(encoded.len() >= 16);
        // Check magic number
        assert_eq!(
            u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]),
            MAGIC_NUMBER
        );
        // Check message number
        assert_eq!(u16::from_be_bytes([encoded[4], encoded[5]]), 1234);
    }

    #[test]
    fn test_roundtrip() {
        let original = InmarsatCMessage {
            message_number: 1234,
            destination_id: "01020304".to_string(),
            source_id: "05060708".to_string(),
            payload: Bytes::from("Hello"),
        };

        let encoded = original.encode();
        let decoded = InmarsatCMessage::parse(&encoded).unwrap();

        assert_eq!(decoded.message_number, original.message_number);
        assert_eq!(decoded.destination_id, original.destination_id);
        assert_eq!(decoded.source_id, original.source_id);
        assert_eq!(decoded.payload, original.payload);
    }
}
