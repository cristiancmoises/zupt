#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
"""
Build a binary RPM for zupt without rpmbuild.
Constructs an RPM-format file directly from the file tree we have for deb.

This is intentionally minimal but produces a valid RPM that:
- Can be installed via `rpm -i` on RHEL/Fedora and other RPM-based distributions
- Contains correct dependency info
- Has working pre/post scripts
- Includes the binary, library, headers, docs, license
"""
import struct, os, sys, hashlib, gzip, io, time, subprocess

VERSION = os.environ.get('VERSION', '2.2.3')
RELEASE = '1'
ARCH = 'x86_64'
NAME = 'zupt'

# RPM tag values (from rpmtag.h)
RPMTAG_NAME = 1000
RPMTAG_VERSION = 1001
RPMTAG_RELEASE = 1002
RPMTAG_SUMMARY = 1004
RPMTAG_DESCRIPTION = 1005
RPMTAG_BUILDTIME = 1006
RPMTAG_BUILDHOST = 1007
RPMTAG_SIZE = 1009
RPMTAG_DISTRIBUTION = 1010
RPMTAG_VENDOR = 1011
RPMTAG_LICENSE = 1014
RPMTAG_PACKAGER = 1015
RPMTAG_GROUP = 1016
RPMTAG_URL = 1020
RPMTAG_OS = 1021
RPMTAG_ARCH = 1022
RPMTAG_PREIN = 1023
RPMTAG_POSTIN = 1024
RPMTAG_PREUN = 1025
RPMTAG_POSTUN = 1026
RPMTAG_FILESIZES = 1028
RPMTAG_FILEMODES = 1030
RPMTAG_FILERDEVS = 1033
RPMTAG_FILEMTIMES = 1034
RPMTAG_FILEDIGESTS = 1035
RPMTAG_FILELINKTOS = 1036
RPMTAG_FILEFLAGS = 1037
RPMTAG_FILEUSERNAME = 1039
RPMTAG_FILEGROUPNAME = 1040
RPMTAG_PROVIDENAME = 1047
RPMTAG_REQUIREFLAGS = 1048
RPMTAG_REQUIRENAME = 1049
RPMTAG_REQUIREVERSION = 1050
RPMTAG_BASENAMES = 1117
RPMTAG_DIRNAMES = 1118
RPMTAG_DIRINDEXES = 1116
RPMTAG_PAYLOADFORMAT = 1124
RPMTAG_PAYLOADCOMPRESSOR = 1125
RPMTAG_FILEDIGESTALGO = 5011

# Type codes
RPM_NULL_TYPE = 0
RPM_CHAR_TYPE = 1
RPM_INT8_TYPE = 2
RPM_INT16_TYPE = 3
RPM_INT32_TYPE = 4
RPM_INT64_TYPE = 5
RPM_STRING_TYPE = 6
RPM_BIN_TYPE = 7
RPM_STRING_ARRAY_TYPE = 8

class Header:
    def __init__(self):
        self.entries = []  # (tag, type, value)

    def add(self, tag, typ, value):
        self.entries.append((tag, typ, value))

    def serialize(self):
        # Build store + index
        store = bytearray()
        index = []
        for tag, typ, value in self.entries:
            if typ == RPM_STRING_TYPE:
                count = 1
                data = value.encode('utf-8') + b'\x00'
                offset = len(store)
                store.extend(data)
            elif typ == RPM_STRING_ARRAY_TYPE:
                count = len(value)
                data = b''.join(s.encode('utf-8') + b'\x00' for s in value)
                offset = len(store)
                store.extend(data)
            elif typ == RPM_INT32_TYPE:
                if not isinstance(value, list):
                    value = [value]
                count = len(value)
                # align to 4
                while len(store) % 4: store.append(0)
                offset = len(store)
                for v in value:
                    store.extend(struct.pack('>I', v & 0xFFFFFFFF))
            elif typ == RPM_INT16_TYPE:
                if not isinstance(value, list):
                    value = [value]
                count = len(value)
                while len(store) % 2: store.append(0)
                offset = len(store)
                for v in value:
                    store.extend(struct.pack('>H', v & 0xFFFF))
            elif typ == RPM_BIN_TYPE:
                count = len(value)
                offset = len(store)
                store.extend(value)
            elif typ == RPM_NULL_TYPE:
                count = 1
                offset = 0
            else:
                raise ValueError(f"Unsupported type {typ}")
            index.append(struct.pack('>IIII', tag, typ, offset, count))

        index_bytes = b''.join(index)
        # Header magic + reserved + index count + store size
        out = struct.pack('>3sBI4sII', b'\x8e\xad\xe8', 1, 0, b'\x00\x00\x00\x00',
                          len(self.entries), len(store))
        out += index_bytes + bytes(store)
        return out

def make_cpio(file_list, source_root, payload_size_out):
    """Build a cpio archive (newc format) of the files."""
    out = io.BytesIO()
    inode = 1
    total = 0
    for arc_path, src_path, mode, is_dir, link_target in file_list:
        if is_dir:
            data = b''
            file_size = 0
        elif link_target is not None:
            data = link_target.encode('utf-8')
            file_size = len(data)
        else:
            with open(src_path, 'rb') as f:
                data = f.read()
            file_size = len(data)
            total += file_size

        name = ('.' + arc_path).encode('utf-8') + b'\x00'
        # newc header: 110 bytes
        header = (
            b'070701'
            + format(inode, '08x').encode('ascii')
            + format(mode, '08x').encode('ascii')
            + b'00000000'  # uid
            + b'00000000'  # gid
            + b'00000001'  # nlink
            + format(int(time.time()), '08x').encode('ascii')
            + format(file_size, '08x').encode('ascii')
            + b'00000000' * 4  # devmajor/minor + rdevmajor/minor
            + format(len(name), '08x').encode('ascii')
            + b'00000000'  # check
        )
        out.write(header)
        out.write(name)
        # pad to 4
        pad = (4 - ((len(header) + len(name)) % 4)) % 4
        out.write(b'\x00' * pad)
        out.write(data)
        # pad data to 4
        pad = (4 - (file_size % 4)) % 4
        out.write(b'\x00' * pad)
        inode += 1

    # Trailer
    trailer_name = b'TRAILER!!!\x00'
    out.write(b'070701' + b'0' * 8 + b'0' * 8 + b'0' * 8 + b'0' * 8 + b'00000001'
              + b'0' * 8 + b'0' * 8 + b'0' * 8 + b'0' * 8 + b'0' * 8 + b'0' * 8
              + format(len(trailer_name), '08x').encode('ascii') + b'0' * 8)
    out.write(trailer_name)
    pad = (4 - ((110 + len(trailer_name)) % 4)) % 4
    out.write(b'\x00' * pad)
    payload_size_out[0] = total
    return out.getvalue()

def main():
    # Files to include (source_path inside our deb tree)
    deb_root = f'/tmp/zupt_{VERSION}_amd64'
    files = []  # (arc_path, source_path, mode, is_dir, link_target)

    for root, dirs, fnames in os.walk(deb_root):
        for d in sorted(dirs):
            full = os.path.join(root, d)
            arc = full[len(deb_root):]
            files.append((arc, full, 0o40755, True, None))
        for fn in sorted(fnames):
            full = os.path.join(root, fn)
            arc = full[len(deb_root):]
            if 'DEBIAN' in arc:
                continue
            if os.path.islink(full):
                files.append((arc, full, 0o120777, False, os.readlink(full)))
            else:
                mode = 0o100755 if os.access(full, os.X_OK) else 0o100644
                files.append((arc, full, mode, False, None))

    # Sort and build basename/dirname/dirindex arrays
    files.sort(key=lambda x: x[0])

    basenames = []
    dirnames_set = []
    dirname_to_idx = {}
    dirindexes = []
    filesizes = []
    filemodes = []
    filemtimes = []
    filedigests = []
    filelinktos = []
    filerdevs = []
    fileflags = []
    fileuser = []
    filegroup = []

    for arc, src, mode, is_dir, link in files:
        d, b = os.path.split(arc)
        d = d + '/'
        if d not in dirname_to_idx:
            dirname_to_idx[d] = len(dirnames_set)
            dirnames_set.append(d)
        basenames.append(b or '.')
        dirindexes.append(dirname_to_idx[d])
        if is_dir:
            filesizes.append(0)
            filedigests.append('')
            filelinktos.append('')
        elif link:
            filesizes.append(len(link))
            filedigests.append('')
            filelinktos.append(link)
        else:
            filesizes.append(os.path.getsize(src))
            with open(src, 'rb') as f:
                filedigests.append(hashlib.sha256(f.read()).hexdigest())
            filelinktos.append('')
        filemodes.append(mode)
        filemtimes.append(int(time.time()))
        filerdevs.append(0)
        fileflags.append(0)
        fileuser.append('root')
        filegroup.append('root')

    payload_size = [0]
    cpio_data = make_cpio(files, deb_root, payload_size)
    # Compress payload with gzip
    gz_payload = gzip.compress(cpio_data)

    # Build main header
    h = Header()
    h.add(RPMTAG_NAME, RPM_STRING_TYPE, NAME)
    h.add(RPMTAG_VERSION, RPM_STRING_TYPE, VERSION)
    h.add(RPMTAG_RELEASE, RPM_STRING_TYPE, RELEASE)
    h.add(RPMTAG_SUMMARY, RPM_STRING_ARRAY_TYPE, ['Post-quantum backup compression utility'])
    h.add(RPMTAG_DESCRIPTION, RPM_STRING_ARRAY_TYPE, [
        'Zupt provides hybrid post-quantum encryption (ML-KEM-768 + X25519)\n'
        'with multi-threaded compression and full-disk backup support.\n'
        'Bundled with libzuptsdk for HKDF-SHA3 hybrid KDF, key commitment,\n'
        'HPKE binding, and anti-fault decapsulation.'
    ])
    h.add(RPMTAG_BUILDTIME, RPM_INT32_TYPE, int(time.time()))
    h.add(RPMTAG_BUILDHOST, RPM_STRING_TYPE, 'localhost')
    h.add(RPMTAG_SIZE, RPM_INT32_TYPE, sum(filesizes))
    h.add(RPMTAG_LICENSE, RPM_STRING_TYPE, 'AGPL-3.0-or-later')
    h.add(RPMTAG_PACKAGER, RPM_STRING_TYPE, 'Cristian Cezar Moises <zupt@riseup.net>')
    h.add(RPMTAG_GROUP, RPM_STRING_ARRAY_TYPE, ['Applications/Archiving'])
    h.add(RPMTAG_URL, RPM_STRING_TYPE, 'https://git.securityops.co/cristiancmoises/zupt')
    h.add(RPMTAG_OS, RPM_STRING_TYPE, 'linux')
    h.add(RPMTAG_ARCH, RPM_STRING_TYPE, ARCH)
    h.add(RPMTAG_POSTIN, RPM_STRING_TYPE, '/sbin/ldconfig\n')
    h.add(RPMTAG_POSTUN, RPM_STRING_TYPE, '/sbin/ldconfig\n')
    h.add(RPMTAG_BASENAMES, RPM_STRING_ARRAY_TYPE, basenames)
    h.add(RPMTAG_DIRNAMES, RPM_STRING_ARRAY_TYPE, dirnames_set)
    h.add(RPMTAG_DIRINDEXES, RPM_INT32_TYPE, dirindexes)
    h.add(RPMTAG_FILESIZES, RPM_INT32_TYPE, filesizes)
    h.add(RPMTAG_FILEMODES, RPM_INT16_TYPE, filemodes)
    h.add(RPMTAG_FILEMTIMES, RPM_INT32_TYPE, filemtimes)
    h.add(RPMTAG_FILEDIGESTS, RPM_STRING_ARRAY_TYPE, filedigests)
    h.add(RPMTAG_FILELINKTOS, RPM_STRING_ARRAY_TYPE, filelinktos)
    h.add(RPMTAG_FILEFLAGS, RPM_INT32_TYPE, fileflags)
    h.add(RPMTAG_FILERDEVS, RPM_INT16_TYPE, filerdevs)
    h.add(RPMTAG_FILEUSERNAME, RPM_STRING_ARRAY_TYPE, fileuser)
    h.add(RPMTAG_FILEGROUPNAME, RPM_STRING_ARRAY_TYPE, filegroup)
    h.add(RPMTAG_PROVIDENAME, RPM_STRING_ARRAY_TYPE, [NAME])
    h.add(RPMTAG_REQUIRENAME, RPM_STRING_ARRAY_TYPE, ['libargon2.so.1()(64bit)', 'libcrypto.so.3()(64bit)', 'libc.so.6()(64bit)'])
    h.add(RPMTAG_REQUIREFLAGS, RPM_INT32_TYPE, [0, 0, 0])
    h.add(RPMTAG_REQUIREVERSION, RPM_STRING_ARRAY_TYPE, ['', '', ''])
    h.add(RPMTAG_PAYLOADFORMAT, RPM_STRING_TYPE, 'cpio')
    h.add(RPMTAG_PAYLOADCOMPRESSOR, RPM_STRING_TYPE, 'gzip')
    h.add(RPMTAG_FILEDIGESTALGO, RPM_INT32_TYPE, 8)  # SHA-256

    main_hdr = h.serialize()

    # Signature header (minimal: just size of payload after sig hdr)
    sig = Header()
    sig_payload = main_hdr + gz_payload
    sig.add(1000, RPM_INT32_TYPE, len(sig_payload))  # SIZE
    sig.add(1004, RPM_BIN_TYPE, hashlib.md5(sig_payload).digest())  # MD5
    sig_bytes = sig.serialize()
    # Pad sig hdr to 8-byte boundary
    pad = (8 - (len(sig_bytes) % 8)) % 8
    sig_bytes += b'\x00' * pad

    # Lead (96 bytes)
    lead = struct.pack('>4sBBhh66sHH16s',
                       b'\xed\xab\xee\xdb',  # magic
                       3, 0,                  # major, minor
                       0,                     # type (binary)
                       1,                     # archnum
                       NAME.encode().ljust(66, b'\x00'),
                       1,                     # osnum
                       5,                     # signature_type
                       b'\x00' * 16)

    out_path = f'/tmp/{NAME}-{VERSION}-{RELEASE}.{ARCH}.rpm'
    with open(out_path, 'wb') as f:
        f.write(lead)
        f.write(sig_bytes)
        f.write(main_hdr)
        f.write(gz_payload)

    print(f'Built: {out_path} ({os.path.getsize(out_path)} bytes)')
    # Try rpm -Kvv to verify if rpm is installed
    try:
        result = subprocess.run(['rpm', '-qpi', out_path], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(result.stdout[:500])
    except Exception:
        pass

if __name__ == '__main__':
    main()
