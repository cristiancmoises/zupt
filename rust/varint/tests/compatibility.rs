// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Cristian Cezar Moisés
#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use zupt_varint::{decode_varint, encode_varint};

static NEXT_INPUT: AtomicUsize = AtomicUsize::new(0);

// A nonzero helper exit is a protocol/test failure, never a rejected varint.
fn query_oracle(input: &[u8]) -> Result<String, String> {
    let directory = std::env::var_os("ZUPT_VARINT_TEST_DIR").expect("run make test-rust-varint");
    let oracle = std::env::var_os("ZUPT_VARINT_ORACLE").expect("C oracle must be supplied");
    let path = std::path::PathBuf::from(directory).join(format!(
        "input-{}-{}",
        std::process::id(),
        NEXT_INPUT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    file.write_all(input).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let result = Command::new(oracle)
        .stdin(Stdio::from(File::open(&path).unwrap()))
        .output()
        .unwrap();
    std::fs::remove_file(path).unwrap();
    if !result.status.success() {
        return Err(format!("C helper failed: {}", result.status));
    }
    if !result.stderr.is_empty() {
        return Err("unexpected C helper diagnostics".to_owned());
    }
    String::from_utf8(result.stdout).map_err(|error| error.to_string())
}

fn add_case(wire: &mut Vec<u8>, cases: &mut Vec<Vec<u8>>, input: &[u8]) {
    assert!(input.len() <= 32);
    wire.extend_from_slice(&(input.len() as u16).to_le_bytes());
    wire.extend_from_slice(input);
    cases.push(input.to_vec());
}

#[test]
fn actual_c_buffer_and_stream_apis_match_rust() {
    let mut wire = Vec::new();
    let mut cases = Vec::new();
    add_case(&mut wire, &mut cases, &[]);
    for first in 0..=u8::MAX {
        add_case(&mut wire, &mut cases, &[first]);
        for second in 0..=u8::MAX {
            add_case(&mut wire, &mut cases, &[first, second]);
        }
    }
    for prefix in [0x80, 0xff] {
        for last in 0..=u8::MAX {
            let mut input = [prefix; 10];
            input[9] = last;
            add_case(&mut wire, &mut cases, &input);
        }
    }
    let mut values = vec![0, u64::MAX];
    for bit in 1..64 {
        let value = 1u64 << bit;
        values.extend_from_slice(&[value - 1, value, value + 1]);
    }
    let mut state = 0x5a55_5054_5255_5354u64;
    for _ in 0..4096 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        values.push(state);
    }
    for value in values {
        let mut output = [0; 10];
        let length = encode_varint(value, &mut output).unwrap();
        add_case(&mut wire, &mut cases, &output[..length]);
        for truncated in 0..length {
            add_case(&mut wire, &mut cases, &output[..truncated]);
        }
        let mut trailing = output[..length].to_vec();
        trailing.extend_from_slice(&[0xff; 12]);
        add_case(&mut wire, &mut cases, &trailing);
    }
    for length in 2..=10 {
        let mut input = vec![0x80; length];
        input[length - 1] = 0;
        add_case(&mut wire, &mut cases, &input);
    }
    let mut later_terminator = [0x80; 11];
    later_terminator[10] = 1;
    add_case(&mut wire, &mut cases, &later_terminator);
    let reply = query_oracle(&wire).expect("C oracle must complete successfully");
    let lines: Vec<_> = reply.lines().collect();
    assert_eq!(lines.len(), cases.len(), "C response count");
    for (index, (input, line)) in cases.iter().zip(lines).enumerate() {
        // Offset storage also exercises a slice with no alignment guarantee.
        let mut storage = vec![0xa5];
        storage.extend_from_slice(input);
        let decoded = decode_varint(&storage[1..]);
        if line == "ERR" {
            assert!(
                decoded.is_err(),
                "accepted rejected C case {index}: {input:?}"
            );
        } else {
            let fields: Vec<_> = line.split(' ').collect();
            assert_eq!(fields.len(), 2, "malformed C reply");
            let consumed: usize = fields[0].parse().unwrap();
            let value: u64 = fields[1].parse().unwrap();
            assert_eq!(decoded, Ok((value, consumed)), "C case {index}: {input:?}");
            let mut encoded = [0xa5; 10];
            assert_eq!(encode_varint(value, &mut encoded), Ok(consumed));
            assert_eq!(&encoded[..consumed], &input[..consumed]);
        }
    }
    println!(
        "PASS: {} real C/Rust varint cases; deterministic seed 0x5a55505452555354",
        cases.len()
    );
}

#[test]
fn malformed_oracle_protocol_never_becomes_codec_rejection() {
    assert!(query_oracle(&[1]).is_err());
    assert!(query_oracle(&[1, 0]).is_err());
    assert!(query_oracle(&[33, 0]).is_err());
    // The first record produces valid output before the next record fails.
    assert!(query_oracle(&[1, 0, 42, 1]).is_err());
}
