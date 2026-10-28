// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Cristian Cezar Moisés
#![forbid(unsafe_code)]

use zupt_varint::{decode_varint, encode_varint, VarintError};

fn vectors() -> Vec<(u64, Vec<u8>)> {
    vec![
        (0, vec![0]),
        (1, vec![1]),
        (127, vec![0x7f]),
        (128, vec![0x80, 1]),
        (255, vec![0xff, 1]),
        (16_383, vec![0xff, 0x7f]),
        (16_384, vec![0x80, 0x80, 1]),
        (
            1u64 << 63,
            vec![0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 1],
        ),
        (
            u64::MAX,
            vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1],
        ),
    ]
}

#[test]
fn known_wire_values() {
    for (value, bytes) in vectors() {
        assert_eq!(decode_varint(&bytes), Ok((value, bytes.len())));
        let mut output = [0xa5; 10];
        assert_eq!(encode_varint(value, &mut output), Ok(bytes.len()));
        assert_eq!(&output[..bytes.len()], bytes);
        assert!(output[bytes.len()..].iter().all(|&byte| byte == 0xa5));
    }
}

#[test]
fn every_proper_prefix_is_truncated() {
    for (_, bytes) in vectors() {
        for length in 0..bytes.len() {
            assert_eq!(decode_varint(&bytes[..length]), Err(VarintError::Truncated));
        }
    }
}

#[test]
fn reject_overlong_final_zero() {
    for length in 2..=10 {
        let mut bytes = vec![0x80; length];
        bytes[length - 1] = 0;
        assert_eq!(decode_varint(&bytes), Err(VarintError::NonCanonical));
    }
}

#[test]
fn tenth_byte_is_checked_before_shift() {
    for prefix in [0x80, 0xff] {
        let mut bytes = [prefix; 10];
        for last in 2..=u8::MAX {
            bytes[9] = last;
            assert_eq!(decode_varint(&bytes), Err(VarintError::Overflow));
        }
        bytes[9] = 1;
        let value = if prefix == 0x80 { 1u64 << 63 } else { u64::MAX };
        assert_eq!(decode_varint(&bytes), Ok((value, 10)));
    }
    assert_eq!(decode_varint(&[0x80; 11]), Err(VarintError::Overflow));
    let mut later_terminator = [0x80; 11];
    later_terminator[10] = 1;
    assert_eq!(decode_varint(&later_terminator), Err(VarintError::Overflow));
}

#[test]
fn trailing_input_is_not_consumed() {
    for (value, mut bytes) in vectors() {
        let consumed = bytes.len();
        bytes.extend_from_slice(&[0xff; 16]);
        assert_eq!(decode_varint(&bytes), Ok((value, consumed)));
    }
}

#[test]
fn offset_slices_do_not_require_alignment() {
    for (value, bytes) in vectors() {
        for offset in 1..=7 {
            let mut storage = vec![0xa5; offset + bytes.len() + 1];
            storage[offset..offset + bytes.len()].copy_from_slice(&bytes);
            assert_eq!(decode_varint(&storage[offset..]), Ok((value, bytes.len())));
        }
    }
}

#[test]
fn short_output_is_unchanged() {
    for (value, bytes) in vectors() {
        for capacity in 0..bytes.len() {
            let mut storage = [0xa5; 12];
            assert_eq!(
                encode_varint(value, &mut storage[1..1 + capacity]),
                Err(VarintError::OutputTooSmall)
            );
            assert_eq!(storage, [0xa5; 12]);
        }
        let mut storage = [0xa5; 12];
        assert_eq!(
            encode_varint(value, &mut storage[1..1 + bytes.len()]),
            Ok(bytes.len())
        );
        assert_eq!(&storage[1..1 + bytes.len()], bytes);
        assert_eq!(storage[0], 0xa5);
        assert!(storage[1 + bytes.len()..].iter().all(|&byte| byte == 0xa5));
    }
}

#[test]
fn bit_boundaries_and_deterministic_values_round_trip() {
    let mut values = vec![0, u64::MAX];
    for shift in 1..64 {
        let value = 1u64 << shift;
        values.extend_from_slice(&[value - 1, value, value + 1]);
    }
    let mut state = 0x5a55_5054_5255_5354u64;
    for _ in 0..10_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        values.push(state);
    }
    for value in values {
        let mut output = [0; 10];
        let length = encode_varint(value, &mut output).unwrap();
        assert_eq!(decode_varint(&output[..length]), Ok((value, length)));
        assert!(length == 1 || output[length - 1] != 0);
    }
}

#[test]
fn large_input_only_decodes_the_first_scalar() {
    let mut input = vec![0xff; 1024 * 1024];
    input[0] = 42;
    assert_eq!(decode_varint(&input), Ok((42, 1)));
    input[0] = 0xff;
    assert_eq!(decode_varint(&input), Err(VarintError::Overflow));
}
