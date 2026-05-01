"""
zuptsdk — Python bindings for libzuptsdk

Copyright (c) 2026 Cristian Cezar Moisés
SPDX-License-Identifier: AGPL-3.0-or-later

Reference Python bindings generated via cffi. Provides a Pythonic API
on top of the C ABI; secrets (passwords, keys) are managed in
mlock-backed buffers that zero on garbage collection.

Quick start:
    import zuptsdk
    with zuptsdk.Context() as ctx:
        archive = ctx.compress_buffer(b"hello world", name="hello.txt",
                                      password=b"secret")
        data = ctx.extract_buffer(archive, password=b"secret")
        assert data == b"hello world"

Post-quantum:
    with zuptsdk.Context() as ctx:
        keypair = ctx.generate_keypair()
        keypair.save("/tmp/mykey")
        archive = ctx.compress_buffer(b"hello", name="h.txt",
                                      public_key=keypair.public)
        data = ctx.extract_buffer(archive, private_key=keypair.private)
"""

import os
from cffi import FFI

# ─────────────────────────────────────────────────────────────────────
# CFFI setup
# ─────────────────────────────────────────────────────────────────────
_ffi = FFI()
_ffi.cdef("""
    typedef struct zuptsdk_ctx          zuptsdk_ctx_t;
    typedef struct zuptsdk_options      zuptsdk_options_t;
    typedef struct zuptsdk_archive_info zuptsdk_archive_info_t;
    typedef struct zuptsdk_secure_buf   zuptsdk_secure_buf_t;
    typedef struct zuptsdk_keypair      zuptsdk_keypair_t;
    typedef struct zuptsdk_pubkey       zuptsdk_pubkey_t;
    typedef struct zuptsdk_privkey      zuptsdk_privkey_t;

    const char *zuptsdk_version_string(void);
    int zuptsdk_version_check(int major, int minor, int patch);
    const char *zuptsdk_strerror(int err);
    const char *zuptsdk_last_error_detail(void);

    int  zuptsdk_ctx_create(zuptsdk_ctx_t **ctx_out);
    void zuptsdk_ctx_destroy(zuptsdk_ctx_t *ctx);
    int  zuptsdk_ctx_set_threads(zuptsdk_ctx_t *ctx, int threads);

    int  zuptsdk_options_create(zuptsdk_options_t **opts_out);
    void zuptsdk_options_destroy(zuptsdk_options_t *opts);
    int  zuptsdk_options_set_codec(zuptsdk_options_t *opts, int codec);
    int  zuptsdk_options_set_level(zuptsdk_options_t *opts, int level);
    int  zuptsdk_options_set_dedup(zuptsdk_options_t *opts, int enabled);
    int  zuptsdk_options_set_solid(zuptsdk_options_t *opts, int enabled);

    int  zuptsdk_secure_buf_create(size_t size, zuptsdk_secure_buf_t **buf_out);
    void zuptsdk_secure_buf_destroy(zuptsdk_secure_buf_t *buf);
    int  zuptsdk_secure_buf_get(zuptsdk_secure_buf_t *buf,
                                uint8_t **data_out, size_t *size_out);
    int  zuptsdk_secure_buf_from_data(const uint8_t *data, size_t size,
                                      zuptsdk_secure_buf_t **buf_out);

    int  zuptsdk_keypair_generate(zuptsdk_ctx_t *ctx, zuptsdk_keypair_t **kp_out);
    void zuptsdk_keypair_destroy(zuptsdk_keypair_t *kp);
    int  zuptsdk_keypair_save_private(const zuptsdk_keypair_t *kp, const char *path);
    int  zuptsdk_keypair_save_public(const zuptsdk_keypair_t *kp, const char *path);
    int  zuptsdk_privkey_load(const char *path, zuptsdk_privkey_t **key_out);
    void zuptsdk_privkey_destroy(zuptsdk_privkey_t *key);
    int  zuptsdk_pubkey_load(const char *path, zuptsdk_pubkey_t **key_out);
    void zuptsdk_pubkey_destroy(zuptsdk_pubkey_t *key);

    int  zuptsdk_compress_buffer(zuptsdk_ctx_t *ctx,
                                 const zuptsdk_options_t *opts,
                                 const char *logical_name,
                                 const uint8_t *data, size_t data_sz,
                                 zuptsdk_secure_buf_t *password,
                                 const zuptsdk_pubkey_t *recipient_pk,
                                 uint8_t **archive_out, size_t *archive_sz);

    int  zuptsdk_extract_buffer(zuptsdk_ctx_t *ctx,
                                const uint8_t *archive, size_t archive_sz,
                                zuptsdk_secure_buf_t *password,
                                const zuptsdk_privkey_t *recipient_sk,
                                uint8_t **data_out, size_t *data_sz);

    int  zuptsdk_extract_to_dir(zuptsdk_ctx_t *ctx,
                                const uint8_t *archive, size_t archive_sz,
                                const char *dest_dir,
                                zuptsdk_secure_buf_t *password,
                                const zuptsdk_privkey_t *recipient_sk);

    int  zuptsdk_verify(zuptsdk_ctx_t *ctx,
                        const uint8_t *archive, size_t archive_sz,
                        zuptsdk_secure_buf_t *password,
                        const zuptsdk_privkey_t *recipient_sk);

    int  zuptsdk_archive_info_read(zuptsdk_ctx_t *ctx,
                                   const uint8_t *archive, size_t archive_sz,
                                   zuptsdk_archive_info_t **info_out);
    void zuptsdk_archive_info_destroy(zuptsdk_archive_info_t *info);
    int      zuptsdk_archive_info_format_major(const zuptsdk_archive_info_t *i);
    int      zuptsdk_archive_info_format_minor(const zuptsdk_archive_info_t *i);
    const char *zuptsdk_archive_info_uuid(const zuptsdk_archive_info_t *i);
    int64_t  zuptsdk_archive_info_created_unix(const zuptsdk_archive_info_t *i);
    uint64_t zuptsdk_archive_info_size(const zuptsdk_archive_info_t *i);
    int      zuptsdk_archive_info_is_encrypted(const zuptsdk_archive_info_t *i);
    int      zuptsdk_archive_info_is_pq_hybrid(const zuptsdk_archive_info_t *i);
    int      zuptsdk_archive_info_is_solid(const zuptsdk_archive_info_t *i);
    int      zuptsdk_archive_info_is_dedup(const zuptsdk_archive_info_t *i);

    void zuptsdk_free(void *ptr);
""")

# Try multiple paths to find the library
def _load_library():
    candidates = [
        os.environ.get("ZUPTSDK_LIBRARY"),
        "libzuptsdk.so.1",
        "libzuptsdk.so",
        "/usr/local/lib/libzuptsdk.so.1",
        "/usr/lib/libzuptsdk.so.1",
    ]
    # Also try ../build relative to this file (dev mode)
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(here, "..", "..", "build", "libzuptsdk.so.1"))
    candidates.append(os.path.join(here, "..", "..", "build", "libzuptsdk.so"))

    last_err = None
    for c in candidates:
        if not c:
            continue
        try:
            return _ffi.dlopen(c)
        except OSError as e:
            last_err = e
    raise OSError(f"Could not load libzuptsdk.so.1 ({last_err}). "
                  f"Set ZUPTSDK_LIBRARY env var or install the library.")

_lib = _load_library()


# ─────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────

class Codec:
    AUTO     = 0
    VAPTVUPT = 1
    LZHP     = 2
    LZH      = 3
    LZ       = 4
    STORE    = 5


class _Errors:
    OK                     = 0
    INVALID_ARG            = -1
    NO_MEMORY              = -2
    IO                     = -3
    BAD_ARCHIVE            = -4
    BAD_PASSWORD           = -5
    BAD_KEY                = -6
    BAD_MAC                = -7
    BAD_VERSION            = -8
    BAD_CHECKSUM           = -9
    BUFFER_TOO_SMALL       = -10
    NOT_ENCRYPTED          = -11
    PASSWORD_REQUIRED      = -12
    PQ_KEY_REQUIRED        = -13
    UNSUPPORTED            = -14


# ─────────────────────────────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────────────────────────────

class ZuptError(Exception):
    """Base exception for any libzuptsdk error."""
    def __init__(self, code, detail=None):
        self.code = code
        msg = _ffi.string(_lib.zuptsdk_strerror(code)).decode("utf-8", "replace")
        if detail:
            msg = f"{msg}: {detail}"
        super().__init__(msg)


class BadPassword(ZuptError):    pass
class BadKey(ZuptError):         pass
class BadArchive(ZuptError):     pass
class PasswordRequired(ZuptError): pass
class PQKeyRequired(ZuptError):  pass


def _check(rc):
    """Raise the right exception for any non-OK return code."""
    if rc == _Errors.OK:
        return
    detail = _ffi.string(_lib.zuptsdk_last_error_detail()).decode("utf-8", "replace")
    if rc == _Errors.BAD_PASSWORD:        raise BadPassword(rc, detail)
    if rc == _Errors.BAD_KEY:             raise BadKey(rc, detail)
    if rc == _Errors.BAD_ARCHIVE:         raise BadArchive(rc, detail)
    if rc == _Errors.PASSWORD_REQUIRED:   raise PasswordRequired(rc, detail)
    if rc == _Errors.PQ_KEY_REQUIRED:     raise PQKeyRequired(rc, detail)
    raise ZuptError(rc, detail)


# ─────────────────────────────────────────────────────────────────────
# SecureBuf — helper to wrap a Python bytes into an mlock'd buffer
# ─────────────────────────────────────────────────────────────────────

class SecureBuf:
    """A secure buffer for passwords or key material. Memory is mlock'd
    and zeroed on close. Use as a context manager."""

    def __init__(self, data):
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("SecureBuf takes bytes")
        self._buf_pp = _ffi.new("zuptsdk_secure_buf_t **")
        rc = _lib.zuptsdk_secure_buf_from_data(data, len(data), self._buf_pp)
        _check(rc)
        self._buf = self._buf_pp[0]

    def _handle(self):
        return self._buf

    def close(self):
        if self._buf:
            _lib.zuptsdk_secure_buf_destroy(self._buf)
            self._buf = _ffi.NULL

    def __enter__(self): return self
    def __exit__(self, *a): self.close()
    def __del__(self):
        try: self.close()
        except Exception: pass


# ─────────────────────────────────────────────────────────────────────
# Keypair, PublicKey, PrivateKey
# ─────────────────────────────────────────────────────────────────────

class PublicKey:
    def __init__(self, path):
        kp = _ffi.new("zuptsdk_pubkey_t **")
        _check(_lib.zuptsdk_pubkey_load(path.encode("utf-8"), kp))
        self._key = kp[0]
    def _handle(self): return self._key
    def __del__(self):
        try:
            if self._key:
                _lib.zuptsdk_pubkey_destroy(self._key)
                self._key = _ffi.NULL
        except Exception: pass


class PrivateKey:
    def __init__(self, path):
        kp = _ffi.new("zuptsdk_privkey_t **")
        _check(_lib.zuptsdk_privkey_load(path.encode("utf-8"), kp))
        self._key = kp[0]
    def _handle(self): return self._key
    def __del__(self):
        try:
            if self._key:
                _lib.zuptsdk_privkey_destroy(self._key)
                self._key = _ffi.NULL
        except Exception: pass


class Keypair:
    """Generated PQ hybrid keypair. Wraps internal temporary files;
    use save() to persist the key material."""

    def __init__(self, ctx_handle):
        kp = _ffi.new("zuptsdk_keypair_t **")
        _check(_lib.zuptsdk_keypair_generate(ctx_handle, kp))
        self._kp = kp[0]
        self._priv_path = None
        self._pub_path = None

    def save(self, base_path):
        """Save keypair as <base_path>.key (private) and <base_path>.pub.
        Private key is written with mode 0600."""
        priv = base_path + ".key"
        pub  = base_path + ".pub"
        _check(_lib.zuptsdk_keypair_save_private(self._kp, priv.encode("utf-8")))
        _check(_lib.zuptsdk_keypair_save_public(self._kp, pub.encode("utf-8")))
        self._priv_path, self._pub_path = priv, pub
        return priv, pub

    @property
    def public(self):
        if not self._pub_path:
            raise RuntimeError("save() the keypair before accessing keys")
        return PublicKey(self._pub_path)

    @property
    def private(self):
        if not self._priv_path:
            raise RuntimeError("save() the keypair before accessing keys")
        return PrivateKey(self._priv_path)

    def __del__(self):
        try:
            if self._kp:
                _lib.zuptsdk_keypair_destroy(self._kp)
                self._kp = _ffi.NULL
        except Exception: pass


# ─────────────────────────────────────────────────────────────────────
# ArchiveInfo
# ─────────────────────────────────────────────────────────────────────

class ArchiveInfo:
    def __init__(self, handle):
        self._h = handle
        # Snapshot fields immediately so handle can be freed
        self.format_major  = int(_lib.zuptsdk_archive_info_format_major(handle))
        self.format_minor  = int(_lib.zuptsdk_archive_info_format_minor(handle))
        uuid_p = _lib.zuptsdk_archive_info_uuid(handle)
        self.uuid          = _ffi.string(uuid_p).decode("utf-8") if uuid_p else ""
        self.created_unix  = int(_lib.zuptsdk_archive_info_created_unix(handle))
        self.size          = int(_lib.zuptsdk_archive_info_size(handle))
        self.is_encrypted  = bool(_lib.zuptsdk_archive_info_is_encrypted(handle))
        self.is_pq_hybrid  = bool(_lib.zuptsdk_archive_info_is_pq_hybrid(handle))
        self.is_solid      = bool(_lib.zuptsdk_archive_info_is_solid(handle))
        self.is_dedup      = bool(_lib.zuptsdk_archive_info_is_dedup(handle))
        _lib.zuptsdk_archive_info_destroy(handle)
        self._h = None

    def __repr__(self):
        return (f"<ArchiveInfo v{self.format_major}.{self.format_minor} "
                f"uuid={self.uuid} encrypted={self.is_encrypted} "
                f"pq={self.is_pq_hybrid} size={self.size}>")


# ─────────────────────────────────────────────────────────────────────
# Options
# ─────────────────────────────────────────────────────────────────────

class _Options:
    def __init__(self, codec=Codec.AUTO, level=7, dedup=False, solid=False):
        op = _ffi.new("zuptsdk_options_t **")
        _check(_lib.zuptsdk_options_create(op))
        self._o = op[0]
        _check(_lib.zuptsdk_options_set_codec(self._o, codec))
        _check(_lib.zuptsdk_options_set_level(self._o, level))
        _check(_lib.zuptsdk_options_set_dedup(self._o, 1 if dedup else 0))
        _check(_lib.zuptsdk_options_set_solid(self._o, 1 if solid else 0))

    def _handle(self): return self._o

    def __del__(self):
        try:
            if self._o:
                _lib.zuptsdk_options_destroy(self._o)
                self._o = _ffi.NULL
        except Exception: pass


# ─────────────────────────────────────────────────────────────────────
# Context — main entry point
# ─────────────────────────────────────────────────────────────────────

class Context:
    """SDK context. Holds thread pool, callbacks, error state."""

    def __init__(self, threads=0):
        cp = _ffi.new("zuptsdk_ctx_t **")
        _check(_lib.zuptsdk_ctx_create(cp))
        self._ctx = cp[0]
        if threads:
            _check(_lib.zuptsdk_ctx_set_threads(self._ctx, threads))

    def __enter__(self): return self
    def __exit__(self, *a): self.close()

    def close(self):
        if self._ctx:
            _lib.zuptsdk_ctx_destroy(self._ctx)
            self._ctx = _ffi.NULL

    def __del__(self):
        try: self.close()
        except Exception: pass

    # ──── helpers ────
    def _password(self, pw):
        """Coerce bytes/SecureBuf/None -> handle."""
        if pw is None: return _ffi.NULL
        if isinstance(pw, SecureBuf): return pw._handle()
        if isinstance(pw, (bytes, bytearray)):
            self._tmp_pw = SecureBuf(bytes(pw))
            return self._tmp_pw._handle()
        raise TypeError("password must be bytes, SecureBuf, or None")

    # ──── operations ────
    def compress_buffer(self, data, name="data.bin",
                        password=None, public_key=None,
                        codec=Codec.AUTO, level=7, dedup=False, solid=False):
        """Compress a single in-memory buffer. Returns archive bytes."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes")
        opts = _Options(codec=codec, level=level, dedup=dedup, solid=solid)
        pw_h = self._password(password)
        pk_h = public_key._handle() if public_key else _ffi.NULL

        out_p  = _ffi.new("uint8_t **")
        out_sz = _ffi.new("size_t *")
        _check(_lib.zuptsdk_compress_buffer(self._ctx, opts._handle(),
                                            name.encode("utf-8"),
                                            data, len(data),
                                            pw_h, pk_h, out_p, out_sz))
        result = bytes(_ffi.buffer(out_p[0], out_sz[0]))
        _lib.zuptsdk_free(out_p[0])
        return result

    def extract_buffer(self, archive, password=None, private_key=None):
        """Extract a single-file archive back to bytes."""
        if not isinstance(archive, (bytes, bytearray)):
            raise TypeError("archive must be bytes")
        pw_h = self._password(password)
        sk_h = private_key._handle() if private_key else _ffi.NULL

        out_p  = _ffi.new("uint8_t **")
        out_sz = _ffi.new("size_t *")
        _check(_lib.zuptsdk_extract_buffer(self._ctx, archive, len(archive),
                                           pw_h, sk_h, out_p, out_sz))
        result = bytes(_ffi.buffer(out_p[0], out_sz[0]))
        _lib.zuptsdk_free(out_p[0])
        return result

    def extract_to_dir(self, archive, dest_dir, password=None, private_key=None):
        if not isinstance(archive, (bytes, bytearray)):
            raise TypeError("archive must be bytes")
        pw_h = self._password(password)
        sk_h = private_key._handle() if private_key else _ffi.NULL
        _check(_lib.zuptsdk_extract_to_dir(self._ctx, archive, len(archive),
                                           dest_dir.encode("utf-8"),
                                           pw_h, sk_h))

    def verify(self, archive, password=None, private_key=None):
        """Verify an archive's integrity. Returns True or raises."""
        pw_h = self._password(password)
        sk_h = private_key._handle() if private_key else _ffi.NULL
        _check(_lib.zuptsdk_verify(self._ctx, archive, len(archive), pw_h, sk_h))
        return True

    def info(self, archive):
        """Read archive header metadata. No password/key needed."""
        info_p = _ffi.new("zuptsdk_archive_info_t **")
        _check(_lib.zuptsdk_archive_info_read(self._ctx, archive, len(archive), info_p))
        return ArchiveInfo(info_p[0])

    def generate_keypair(self):
        return Keypair(self._ctx)


# ─────────────────────────────────────────────────────────────────────
# Module info
# ─────────────────────────────────────────────────────────────────────

__version__ = _ffi.string(_lib.zuptsdk_version_string()).decode("utf-8")
