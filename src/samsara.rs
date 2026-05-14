//! Samsara protocol parsing and encoding
//!
//! Samsara is a fleet management and IoT platform using cellular broadband (LTE/5G).
//! This module provides zero-allocation parsing for Samsara message format.
//!
//! Binary format: [version (1)][device_id_len (2)][device_id (N)][timestamp (8)][latitude (8)][longitude (8)][payload_len (4)][payload (N)]

use bytes::Bytes;

#[derive(Debug, Clone)]
pub struct SamsaraMessage {
    pub device_id: String,
    pub timestamp: u64,
    pub latitude: f64,
    pub longitude: f64,
    pub payload: Bytes,
}

impl SamsaraMessage {
    /// Parse Samsara message from bytes (zero-allocation)
    /// Binary format: [version (1)][device_id_len (2)][device_id (N)][timestamp (8)][latitude (8)][longitude (8)][payload_len (4)][payload (N)]
    pub fn parse(data: &[u8]) -> Option<Self> {
        // Minimum size: version(1) + device_id_len(2) + timestamp(8) + latitude(8) + longitude(8) + payload_len(4) = 31 bytes
        if data.len() < 31 {
            return None;
        }

        let version = data[0];
        if version != 1 {
            return None; // Unsupported version
        }

        let device_id_len = u16::from_be_bytes([data[1], data[2]]) as usize;
        let header_size = 3 + device_id_len + 24; // 3 + device_id + (8+8+8+4)

        if data.len() < header_size {
            return None;
        }

        let device_id = String::from_utf8(data[3..3 + device_id_len].to_vec()).ok()?;
        let timestamp = u64::from_be_bytes([
            data[3 + device_id_len],
            data[3 + device_id_len + 1],
            data[3 + device_id_len + 2],
            data[3 + device_id_len + 3],
            data[3 + device_id_len + 4],
            data[3 + device_id_len + 5],
            data[3 + device_id_len + 6],
            data[3 + device_id_len + 7],
        ]);

        let latitude = f64::from_be_bytes([
            data[3 + device_id_len + 8],
            data[3 + device_id_len + 9],
            data[3 + device_id_len + 10],
            data[3 + device_id_len + 11],
            data[3 + device_id_len + 12],
            data[3 + device_id_len + 13],
            data[3 + device_id_len + 14],
            data[3 + device_id_len + 15],
        ]);

        let longitude = f64::from_be_bytes([
            data[3 + device_id_len + 16],
            data[3 + device_id_len + 17],
            data[3 + device_id_len + 18],
            data[3 + device_id_len + 19],
            data[3 + device_id_len + 20],
            data[3 + device_id_len + 21],
            data[3 + device_id_len + 22],
            data[3 + device_id_len + 23],
        ]);

        let payload_len = u32::from_be_bytes([
            data[3 + device_id_len + 24],
            data[3 + device_id_len + 25],
            data[3 + device_id_len + 26],
            data[3 + device_id_len + 27],
        ]) as usize;

        let payload_start = 3 + device_id_len + 28; // After payload_len (4 bytes)
        if data.len() < payload_start + payload_len {
            return None;
        }

        let payload = Bytes::copy_from_slice(&data[payload_start..payload_start + payload_len]);

        Some(Self {
            device_id,
            timestamp,
            latitude,
            longitude,
            payload,
        })
    }

    /// Encode Samsara message to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        // Version
        buffer.push(1);

        // Device ID (length-prefixed)
        let device_id_bytes = self.device_id.as_bytes();
        buffer.extend_from_slice(&(device_id_bytes.len() as u16).to_be_bytes());
        buffer.extend_from_slice(device_id_bytes);

        // Timestamp
        buffer.extend_from_slice(&self.timestamp.to_be_bytes());

        // Latitude
        buffer.extend_from_slice(&self.latitude.to_be_bytes());

        // Longitude
        buffer.extend_from_slice(&self.longitude.to_be_bytes());

        // Payload (length-prefixed)
        let payload_len = self.payload.len() as u32;
        buffer.extend_from_slice(&payload_len.to_be_bytes());
        buffer.extend_from_slice(&self.payload);

        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_samsara_parse() {
        let device_id = "device-12345";
        let timestamp = 1234567890u64;
        let latitude = 37.7749_f64;
        let longitude = -122.4194_f64;
        let payload = b"test payload data";

        let mut buffer = Vec::new();
        buffer.push(1); // version
        buffer.extend_from_slice(&(device_id.len() as u16).to_be_bytes());
        buffer.extend_from_slice(device_id.as_bytes());
        buffer.extend_from_slice(&timestamp.to_be_bytes());
        buffer.extend_from_slice(&latitude.to_be_bytes());
        buffer.extend_from_slice(&longitude.to_be_bytes());
        buffer.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buffer.extend_from_slice(payload);

        let msg = SamsaraMessage::parse(&buffer).unwrap();
        assert_eq!(msg.device_id, device_id);
        assert_eq!(msg.timestamp, timestamp);
        assert_eq!(msg.latitude, latitude);
        assert_eq!(msg.longitude, longitude);
        assert_eq!(msg.payload, Bytes::from(&payload[..]));
    }

    #[test]
    fn test_samsara_parse_too_short() {
        let data = b"short";
        let msg = SamsaraMessage::parse(data);
        assert!(msg.is_none());
    }

    #[test]
    fn test_samsara_roundtrip() {
        let original = SamsaraMessage {
            device_id: "device-67890".to_string(),
            timestamp: 9876543210u64,
            latitude: 40.7128_f64,
            longitude: -74.0060_f64,
            payload: Bytes::from(&b"roundtrip test data"[..]),
        };

        let encoded = original.encode();
        let decoded = SamsaraMessage::parse(&encoded).unwrap();

        assert_eq!(decoded.device_id, original.device_id);
        assert_eq!(decoded.timestamp, original.timestamp);
        assert_eq!(decoded.latitude, original.latitude);
        assert_eq!(decoded.longitude, original.longitude);
        assert_eq!(decoded.payload, original.payload);
    }

    #[test]
    fn test_samsara_encode() {
        let msg = SamsaraMessage {
            device_id: "test-device".to_string(),
            timestamp: 1234567890u64,
            latitude: 37.7749_f64,
            longitude: -122.4194_f64,
            payload: Bytes::from(&b"test payload"[..]),
        };

        let encoded = msg.encode();
        assert!(encoded.len() > 31); // Minimum header size
        assert_eq!(encoded[0], 1); // Version
    }
}
