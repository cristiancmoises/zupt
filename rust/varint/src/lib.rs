// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Cristian Cezar Moisés
#![no_std]
#![forbid(unsafe_code)]

//! Canonical unsigned varints used by `src/zupt_format.c`.
//!
//! This optional compatibility core is not linked into the production CLI.
//! It handles scalar wire encoding only, not archive or stream validation.

/// A rejected scalar or insufficient output capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarintError {
    /// Input ends before a terminator, within the ten-byte limit.
    Truncated,
    /// The tenth byte cannot fit in a `u64` or still has a continuation bit.
    Overflow,
    /// A redundant final zero makes the representation noncanonical.
    NonCanonical,
    /// No output bytes were changed because the full scalar would not fit.
    OutputTooSmall,
}

/// Decode one scalar and return its value and consumed length.
///
/// At most ten input bytes are examined. Trailing bytes are left for the caller.
/// Unlike the C out-parameter API, an error exposes no partial scalar value.
///
/// ```
/// assert_eq!(zupt_varint::decode_varint(&[0x80, 1, 42]), Ok((128, 2)));
/// ```
pub fn decode_varint(input: &[u8]) -> Result<(u64, usize), VarintError> {
    let mut value = 0u64;
    for (index, &byte) in input.iter().take(10).enumerate() {
        // Only one payload bit remains in byte ten; validate before shifting.
        if index == 9 && byte & 0xfe != 0 {
            return Err(VarintError::Overflow);
        }
        let payload = byte & 0x7f;
        value |= u64::from(payload) << (index * 7);
        if byte & 0x80 == 0 {
            if index != 0 && payload == 0 {
                return Err(VarintError::NonCanonical);
            }
            return Ok((value, index + 1));
        }
    }
    Err(VarintError::Truncated)
}

/// Write the shortest representation and return the exact produced length.
///
/// On insufficient capacity the complete output slice remains unchanged.
/// On success bytes after the produced prefix remain unchanged.
pub fn encode_varint(value: u64, output: &mut [u8]) -> Result<usize, VarintError> {
    let mut remaining = value;
    let mut needed = 1;
    while remaining >= 0x80 {
        remaining >>= 7;
        needed += 1;
    }
    if output.len() < needed {
        return Err(VarintError::OutputTooSmall);
    }
    remaining = value;
    for byte in &mut output[..needed] {
        *byte = (remaining & 0x7f) as u8;
        remaining >>= 7;
        if remaining != 0 {
            *byte |= 0x80;
        }
    }
    Ok(needed)
}
