#!/usr/bin/env python3
"""
zuptsdk Python binding test
SPDX-License-Identifier: AGPL-3.0-or-later
"""
import os
import sys
import tempfile

# Add path so we can import without installing
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("ZUPTSDK_LIBRARY",
    os.path.join(os.path.dirname(__file__), "..", "..", "build", "libzuptsdk.so.1"))

import zuptsdk

PASS = 0
FAIL = 0

def test(name, fn):
    global PASS, FAIL
    try:
        fn()
        print(f"  {name:<60} PASS")
        PASS += 1
    except Exception as e:
        print(f"  {name:<60} FAIL: {e!r}")
        FAIL += 1


print(f"\n  zuptsdk Python bindings — version {zuptsdk.__version__}\n")

DATA = b"Hello world from Python via cffi!\n" * 10


def t_version():
    assert zuptsdk.__version__ == "1.0.0", f"got {zuptsdk.__version__}"


def t_roundtrip_plain():
    with zuptsdk.Context() as ctx:
        arc = ctx.compress_buffer(DATA, name="hello.txt")
        assert isinstance(arc, bytes)
        assert len(arc) > 0
        out = ctx.extract_buffer(arc)
        assert out == DATA


def t_roundtrip_password():
    with zuptsdk.Context() as ctx:
        arc = ctx.compress_buffer(DATA, name="secret.txt",
                                   password=b"correct horse battery staple")
        out = ctx.extract_buffer(arc, password=b"correct horse battery staple")
        assert out == DATA


def t_wrong_password():
    with zuptsdk.Context() as ctx:
        arc = ctx.compress_buffer(DATA, name="x.txt", password=b"good")
        try:
            ctx.extract_buffer(arc, password=b"bad")
        except zuptsdk.ZuptError:
            return
        raise AssertionError("wrong password was accepted")


def t_secure_buf_password():
    with zuptsdk.Context() as ctx, zuptsdk.SecureBuf(b"locked-pw") as pw:
        arc = ctx.compress_buffer(DATA, name="x.txt", password=pw)
        out = ctx.extract_buffer(arc, password=pw)
        assert out == DATA


def t_pq_keypair():
    with zuptsdk.Context() as ctx:
        kp = ctx.generate_keypair()
        with tempfile.TemporaryDirectory() as td:
            kp.save(os.path.join(td, "mykey"))
            arc = ctx.compress_buffer(DATA, name="pq.txt", public_key=kp.public)
            out = ctx.extract_buffer(arc, private_key=kp.private)
            assert out == DATA


def t_verify_and_info():
    with zuptsdk.Context() as ctx:
        arc = ctx.compress_buffer(DATA, name="v.txt")
        assert ctx.verify(arc) is True
        info = ctx.info(arc)
        assert info.format_major >= 1
        assert info.is_encrypted is False
        assert len(info.uuid) == 36, info.uuid


def t_corrupted_archive():
    with zuptsdk.Context() as ctx:
        # Use enough data that flipping a byte mid-stream lands in the
        # compressed payload, not in a zero-padded region.
        big = DATA * 100
        arc = bytearray(ctx.compress_buffer(big, name="c.txt"))
        # Flip a byte two-thirds of the way through — well into compressed
        # data, well before the index/footer.
        if len(arc) > 200:
            offset = (len(arc) * 2) // 3
            arc[offset] ^= 0xFF
        try:
            ctx.verify(bytes(arc))
        except zuptsdk.ZuptError:
            return
        raise AssertionError("corrupted archive accepted")


test("version constant", t_version)
test("roundtrip plain", t_roundtrip_plain)
test("roundtrip password (bytes)", t_roundtrip_password)
test("wrong password rejected", t_wrong_password)
test("roundtrip with SecureBuf", t_secure_buf_password)
test("PQ keypair generate + roundtrip", t_pq_keypair)
test("verify and info", t_verify_and_info)
test("corrupted archive rejected", t_corrupted_archive)

print(f"\n  Results: {PASS} passed, {FAIL} failed\n")
sys.exit(0 if FAIL == 0 else 1)
