#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deterministic structural fixtures for the actual block-swap test mutation."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / 'tests/test_block_swap.sh'


def varint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def frame(payload, kind=0, flags=1):
    return (b'\xbb\x01' + bytes([kind]) + b'\x10\x00' + flags.to_bytes(2, 'little')
            + varint(len(payload)) + varint(len(payload)) + bytes(8) + payload)


def archive(left, right, false_header=False):
    header = bytearray(64)
    header[:6] = b'ZUPT\x1a\x00'
    if false_header:
        # Random header bytes can resemble an ENC frame declaring a huge
        # payload. The old byte-zero scanner skips every real DATA frame.
        fake = b'\xbb\x01\x03\x00\x00\x00\x00' + varint(1) + varint(1 << 20) + bytes(8)
        header[8:8 + len(fake)] = fake
    index_offset = 64 + len(left) + len(right)
    index = frame(b'index', kind=2, flags=0)
    footer = index_offset.to_bytes(8, 'little') + bytes(16) + b'ZEND' + (1).to_bytes(4, 'little')
    return bytes(header) + left + right + index + footer + bytes(32)


class BlockSwapFixtureTests(unittest.TestCase):
    def mutate(self, data):
        script = SCRIPT.read_text()
        marker = '# P2: The block-swap attack must FAIL (no files extracted, or wrong files rejected)'
        mutation = script.split(marker, 1)[1].split('swap_status=$?', 1)[0]
        with tempfile.TemporaryDirectory(prefix='zupt-block-swap-fixture-') as temporary:
            work = Path(temporary)
            (work / 'archive.zupt').write_bytes(data)
            environment = os.environ.copy()
            environment['surgery'] = str(ROOT / 'tests/archive_surgery.py')
            result = subprocess.run(['bash', '-c', mutation], cwd=work, env=environment,
                                    capture_output=True, text=True, timeout=10)
            output = work / 'archive_swapped.zupt'
            return result, output.read_bytes() if output.exists() else None

    def test_false_header_magic_cannot_hide_real_encrypted_frames(self):
        left, right = frame(b'A' * 32), frame(b'B' * 32)
        original = archive(left, right, false_header=True)
        result, swapped = self.mutate(original)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(swapped, original[:64] + right + left + original[64 + len(left) + len(right):])
        self.assertNotEqual(swapped, original)

    def test_payload_magic_is_not_a_frame_boundary(self):
        fake = b'\xbb\x01\x03\x00\x00\x00\x00' + varint(1) + varint(1 << 20) + bytes(8)
        left, right = frame(fake + b'A' * 32), frame(fake + b'B' * 32)
        original = archive(left, right)
        result, swapped = self.mutate(original)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(swapped, original[:64] + right + left + original[64 + len(left) + len(right):])

    def test_unequal_frame_lengths_are_rejected(self):
        result, swapped = self.mutate(archive(frame(b'A' * 32), frame(b'B' * 33)))
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(swapped)

    def test_identical_frames_are_rejected_as_noop(self):
        result, swapped = self.mutate(archive(frame(b'A' * 32), frame(b'A' * 32)))
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(swapped)

    def test_unencrypted_frames_are_not_selected(self):
        result, swapped = self.mutate(archive(frame(b'A' * 32, flags=0), frame(b'B' * 32, flags=0)))
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(swapped)


if __name__ == '__main__':
    unittest.main(verbosity=2)
