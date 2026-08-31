#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Strict structural mutations used by archive-authentication tests."""

import argparse
import pathlib
import sys


ARCHIVE_HEADER_SIZE = 64
FOOTER_SIZE = 32
AIT_SIZE = 32
BLOCK_DATA = 0x00
BLOCK_INDEX = 0x02
BLOCK_ENC_HEADER = 0x03
BLOCK_DEDUP_REF = 0x04
BLOCK_COMMENT = 0x05
BLOCK_FLAG_ENCRYPTED = 0x01


class ArchiveError(ValueError):
    pass


def _u16le(data, offset):
    return int.from_bytes(data[offset:offset + 2], "little")


def _u64le(data, offset):
    return int.from_bytes(data[offset:offset + 8], "little")


def _read_varint(data, offset, limit):
    value = 0
    for byte_number in range(10):
        if offset >= limit:
            raise ArchiveError("truncated varint")
        byte = data[offset]
        offset += 1
        if byte_number == 9 and byte > 1:
            raise ArchiveError("varint exceeds uint64")
        value |= (byte & 0x7f) << (7 * byte_number)
        if (byte & 0x80) == 0:
            if byte_number and value < (1 << (7 * byte_number)):
                raise ArchiveError("non-canonical varint")
            return value, offset
    raise ArchiveError("unterminated varint")


def _parse_frame(data, offset, limit):
    start = offset
    if limit - offset < 17:
        raise ArchiveError("truncated block header")
    if data[offset:offset + 2] != b"\xbb\x01":
        raise ArchiveError("invalid block magic")
    block_type = data[offset + 2]
    codec = _u16le(data, offset + 3)
    flags = _u16le(data, offset + 5)
    offset += 7
    uncompressed_size, offset = _read_varint(data, offset, limit)
    compressed_size, offset = _read_varint(data, offset, limit)
    if limit - offset < 8:
        raise ArchiveError("truncated block checksum")
    checksum = _u64le(data, offset)
    payload_start = offset + 8
    if compressed_size > limit - payload_start:
        raise ArchiveError("block payload exceeds structural boundary")
    end = payload_start + compressed_size
    return {
        "type": block_type,
        "codec": codec,
        "flags": flags,
        "uncompressed_size": uncompressed_size,
        "compressed_size": compressed_size,
        "checksum": checksum,
        "start": start,
        "payload_start": payload_start,
        "end": end,
    }


def _parse_current_archive(data):
    minimum = ARCHIVE_HEADER_SIZE + FOOTER_SIZE + AIT_SIZE
    if len(data) < minimum:
        raise ArchiveError("archive is too short")
    if data[:6] != b"ZUPT\x1a\x00":
        raise ArchiveError("invalid archive magic")

    footer_start = len(data) - FOOTER_SIZE - AIT_SIZE
    if data[footer_start + 24:footer_start + 28] != b"ZEND":
        raise ArchiveError("current footer before AIT not found")
    if int.from_bytes(data[footer_start + 28:footer_start + 32],
                      "little") != 1:
        raise ArchiveError("unsupported footer version")

    index_offset = _u64le(data, footer_start)
    if index_offset < ARCHIVE_HEADER_SIZE or index_offset >= footer_start:
        raise ArchiveError("index offset is outside the archive body")

    frames = []
    offset = ARCHIVE_HEADER_SIZE
    while offset < index_offset:
        frame = _parse_frame(data, offset, index_offset)
        if frame["type"] == BLOCK_INDEX:
            raise ArchiveError("index frame occurs before footer index offset")
        frames.append(frame)
        offset = frame["end"]
    if offset != index_offset:
        raise ArchiveError("archive body does not end at index offset")

    index = _parse_frame(data, index_offset, footer_start)
    if index["type"] != BLOCK_INDEX:
        raise ArchiveError("footer does not point to an index frame")
    if index["end"] != footer_start:
        raise ArchiveError("bytes remain between index and footer")

    return {
        "frames": frames,
        "index": index,
        "footer_start": footer_start,
    }


def _kind_value(name):
    return {"data": BLOCK_DATA, "enc": BLOCK_ENC_HEADER,
            "ref": BLOCK_DEDUP_REF}[name]


def _matching_frames(layout, kind, require_encrypted):
    matches = [frame for frame in layout["frames"]
               if frame["type"] == _kind_value(kind)]
    if require_encrypted:
        matches = [frame for frame in matches
                   if frame["flags"] & BLOCK_FLAG_ENCRYPTED]
    return matches


def _same_metadata(left, right):
    fields = ("type", "codec", "flags", "uncompressed_size",
              "compressed_size", "checksum")
    return all(left[field] == right[field] for field in fields)


def _select_equal_length_pair(frames, same_metadata):
    for index, left in enumerate(frames):
        for right in frames[index + 1:]:
            if left["end"] - left["start"] != right["end"] - right["start"]:
                continue
            if same_metadata and not _same_metadata(left, right):
                continue
            return left, right
    qualifier = " with identical metadata" if same_metadata else ""
    raise ArchiveError("no two equal-length frames" + qualifier)


def _write(destination, data):
    pathlib.Path(destination).write_bytes(data)


def command_strip_ait(args):
    data = pathlib.Path(args.source).read_bytes()
    layout = _parse_current_archive(data)
    _write(args.destination, data[:layout["footer_start"] + FOOTER_SIZE])


def command_flip_payload(args):
    data = bytearray(pathlib.Path(args.source).read_bytes())
    layout = _parse_current_archive(data)
    frames = _matching_frames(layout, args.kind, args.require_encrypted)
    if not frames:
        raise ArchiveError("requested frame was not found")
    frame = frames[0]
    if frame["compressed_size"] == 0:
        raise ArchiveError("requested frame has no payload")
    position = frame["payload_start"] + frame["compressed_size"] // 2
    data[position] ^= 0x01
    _write(args.destination, data)


def command_swap_frames(args):
    data = bytearray(pathlib.Path(args.source).read_bytes())
    layout = _parse_current_archive(data)
    frames = _matching_frames(layout, args.kind, args.require_encrypted)
    left, right = _select_equal_length_pair(frames, args.same_metadata)
    left_bytes = bytes(data[left["start"]:left["end"]])
    right_bytes = bytes(data[right["start"]:right["end"]])
    if left_bytes == right_bytes:
        raise ArchiveError("selected frames are byte-identical; swap is a no-op")
    data[left["start"]:left["end"]] = right_bytes
    data[right["start"]:right["end"]] = left_bytes
    _write(args.destination, data)


def command_replay_frame(args):
    data = bytearray(pathlib.Path(args.source).read_bytes())
    layout = _parse_current_archive(data)
    frames = _matching_frames(layout, args.kind, args.require_encrypted)
    source, destination = _select_equal_length_pair(frames,
                                                     args.same_metadata)
    replay = bytes(data[source["start"]:source["end"]])
    if replay == bytes(data[destination["start"]:destination["end"]]):
        raise ArchiveError("selected frames are already byte-identical")
    data[destination["start"]:destination["end"]] = replay
    _write(args.destination, data)


def command_preface_positions(args):
    data = pathlib.Path(args.source).read_bytes()
    layout = _parse_current_archive(data)
    for frame in layout["frames"] + [layout["index"]]:
        for position in range(frame["start"], frame["payload_start"]):
            print(position)


def command_set_frame_type(args):
    data = bytearray(pathlib.Path(args.source).read_bytes())
    layout = _parse_current_archive(data)
    frames = _matching_frames(layout, args.kind, args.require_encrypted)
    if not frames:
        raise ArchiveError("requested frame was not found")
    replacement = {"data": BLOCK_DATA, "comment": BLOCK_COMMENT}[args.type]
    data[frames[0]["start"] + 2] = replacement
    _write(args.destination, data)


def _add_frame_options(parser):
    parser.add_argument("source")
    parser.add_argument("destination")
    parser.add_argument("--kind", choices=("data", "enc", "ref"), required=True)
    parser.add_argument("--require-encrypted", action="store_true")


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command")

    strip_ait = commands.add_parser("strip-ait")
    strip_ait.add_argument("source")
    strip_ait.add_argument("destination")
    strip_ait.set_defaults(function=command_strip_ait)

    flip = commands.add_parser("flip-payload")
    _add_frame_options(flip)
    flip.set_defaults(function=command_flip_payload)

    swap = commands.add_parser("swap-frames")
    _add_frame_options(swap)
    swap.add_argument("--same-metadata", action="store_true")
    swap.set_defaults(function=command_swap_frames)

    replay = commands.add_parser("replay-frame")
    _add_frame_options(replay)
    replay.add_argument("--same-metadata", action="store_true")
    replay.set_defaults(function=command_replay_frame)

    prefaces = commands.add_parser("preface-positions")
    prefaces.add_argument("source")
    prefaces.set_defaults(function=command_preface_positions)

    set_type = commands.add_parser("set-frame-type")
    _add_frame_options(set_type)
    set_type.add_argument("--type", choices=("data", "comment"), required=True)
    set_type.set_defaults(function=command_set_frame_type)

    args = parser.parse_args()
    if not hasattr(args, "function"):
        parser.error("a mutation command is required")
    try:
        args.function(args)
    except (ArchiveError, OSError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    sys.exit(main())
