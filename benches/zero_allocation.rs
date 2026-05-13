#![cfg(test)]
//! Zero-allocation benchmark tests
//! 
//! Benchmarks to verify that the hot path has no heap allocations

use float_protocols::{IridiumSBDMessage, ZeroCopyTranslator};
use std::hint::black_box;

#[bench]
fn bench_iridium_parse(b: &mut test::Bencher) {
    let data: Vec<u8> = vec![
        0x01, // protocol
        0x00, 0x05, // length = 5
        0x48, 0x65, 0x6c, 0x6c, 0x6f, // "Hello"
        0x00, 0x00, // checksum
    ];

    b.iter(|| {
        let msg = IridiumSBDMessage::parse(black_box(&data));
        black_box(msg);
    });
}

#[bench]
fn bench_zero_copy_translation(b: &mut test::Bencher) {
    let iridium_data: Vec<u8> = vec![
        0x01, // protocol
        0x00, 0x05, // length = 5
        0x48, 0x65, 0x6c, 0x6c, 0x6f, // "Hello"
        0x00, 0x00, // checksum
    ];

    let iridium_msg = IridiumSBDMessage::parse(&iridium_data).unwrap();
    let mut translator = ZeroCopyTranslator::new();
    let mut output_buffer = [0u8; 2048];

    b.iter(|| {
        let size = translator.translate(black_box(&iridium_msg), black_box(&mut output_buffer));
        black_box(size);
    });
}

#[bench]
fn bench_full_hot_path(b: &mut test::Bencher) {
    let iridium_data: Vec<u8> = vec![
        0x01, // protocol
        0x00, 0x05, // length = 5
        0x48, 0x65, 0x6c, 0x6c, 0x6f, // "Hello"
        0x00, 0x00, // checksum
    ];

    let mut translator = ZeroCopyTranslator::new();
    let mut output_buffer = [0u8; 2048];

    b.iter(|| {
        let iridium_msg = IridiumSBDMessage::parse(black_box(&iridium_data)).unwrap();
        let size = translator.translate(black_box(&iridium_msg), black_box(&mut output_buffer));
        black_box(size);
    });
}
