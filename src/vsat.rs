//! VSAT protocol parsing and encoding with compression
//!
//! VSAT (Very Small Aperture Terminal) IP packets with compression for cellular transmission.

use bytes::Bytes;
use zstd;

#[derive(Debug, Clone)]
pub struct VSATMessage {
    pub packet_id: u32,
    pub source_ip: [u8; 4],
    pub dest_ip: [u8; 4],
    pub payload: Bytes,
}

impl VSATMessage {
    /// Parse VSAT message from bytes (decompressed)
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }

        // VSAT format (simplified):
        // Bytes 0-3: Packet ID (big-endian)
        // Bytes 4-7: Source IP
        // Bytes 8-11: Destination IP
        // Bytes 12-65535: Payload (variable)

        let packet_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let source_ip = [data[4], data[5], data[6], data[7]];
        let dest_ip = [data[8], data[9], data[10], data[11]];
        let payload = Bytes::copy_from_slice(&data[12..]);

        Some(Self {
            packet_id,
            source_ip,
            dest_ip,
            payload,
        })
    }

    /// Encode VSAT message to bytes (compressed)
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = vec![0u8; 12 + self.payload.len()];

        // Packet ID (bytes 0-3)
        buffer[0..4].copy_from_slice(&self.packet_id.to_be_bytes());

        // Source IP (bytes 4-7)
        buffer[4..8].copy_from_slice(&self.source_ip);

        // Destination IP (bytes 8-11)
        buffer[8..12].copy_from_slice(&self.dest_ip);

        // Payload (bytes 12+)
        buffer[12..].copy_from_slice(&self.payload);

        // Compress the buffer
        let compressed = zstd::encode_all(buffer.as_slice(), 3).unwrap_or_else(|_| buffer.clone());
        compressed
    }

    /// Decompress VSAT message
    pub fn decompress(compressed_data: &[u8]) -> Option<Vec<u8>> {
        zstd::decode_all(compressed_data).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vsat_parse() {
        let mut data = vec![0u8; 20];
        data[0..4].copy_from_slice(&12345678u32.to_be_bytes());
        data[4..8].copy_from_slice(&[192, 168, 1, 1]);
        data[8..12].copy_from_slice(&[192, 168, 1, 2]);
        data[12] = b'H';
        data[13] = b'e';
        data[14] = b'l';
        data[15] = b'l';
        data[16] = b'o';

        let msg = VSATMessage::parse(&data);
        assert!(msg.is_some());
        assert_eq!(msg.unwrap().packet_id, 12345678);
    }

    #[test]
    fn test_vsat_parse_too_short() {
        let data = b"short";
        let msg = VSATMessage::parse(data);
        assert!(msg.is_none());
    }

    #[test]
    fn test_vsat_encode() {
        let msg = VSATMessage {
            packet_id: 12345678,
            source_ip: [192, 168, 1, 1],
            dest_ip: [192, 168, 1, 2],
            payload: Bytes::from("Hello"),
        };

        let encoded = msg.encode();
        assert!(encoded.len() >= 12);
    }

    #[test]
    fn test_vsat_compress_decompress() {
        let msg = VSATMessage {
            packet_id: 12345678,
            source_ip: [192, 168, 1, 1],
            dest_ip: [192, 168, 1, 2],
            payload: Bytes::from("Hello VSAT"),
        };

        let compressed = msg.encode();
        let decompressed = VSATMessage::decompress(&compressed);
        assert!(decompressed.is_some());
    }
}
