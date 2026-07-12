// libzuptsdk C++17 header — RAII wrappers, exception-based error handling
// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef ZUPTSDK_HPP
#define ZUPTSDK_HPP

#include "zuptsdk.h"
#include <array>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace zuptsdk {

class Error : public std::runtime_error {
    int code_;
public:
    Error(int code, const std::string& msg) : std::runtime_error(msg), code_(code) {}
    int code() const noexcept { return code_; }
};

inline void check(int rc) {
    if (rc != ZUPTSDK_OK) {
        const char* detail = zuptsdk_last_error_detail();
        throw Error(rc, detail && *detail ? detail : zuptsdk_strerror(rc));
    }
}

// RAII wrapper for SDK-allocated buffers (must be freed via zuptsdk_free)
class Buffer {
    uint8_t* data_;
    std::size_t size_;
public:
    Buffer() : data_(nullptr), size_(0) {}
    Buffer(uint8_t* data, std::size_t size) : data_(data), size_(size) {}
    ~Buffer() { if (data_) zuptsdk_free(data_); }
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;
    Buffer(Buffer&& o) noexcept : data_(o.data_), size_(o.size_) { o.data_ = nullptr; o.size_ = 0; }
    Buffer& operator=(Buffer&& o) noexcept {
        if (data_) zuptsdk_free(data_);
        data_ = o.data_; size_ = o.size_; o.data_ = nullptr; o.size_ = 0;
        return *this;
    }
    const uint8_t* data() const noexcept { return data_; }
    uint8_t* data() noexcept { return data_; }
    std::size_t size() const noexcept { return size_; }
    std::vector<uint8_t> to_vector() const { return {data_, data_ + size_}; }
    uint8_t** out_ptr() noexcept { return &data_; }
    std::size_t* out_size() noexcept { return &size_; }
};

class Context {
    zuptsdk_ctx_t* ctx_;
public:
    Context() : ctx_(nullptr) { check(zuptsdk_ctx_create(&ctx_)); }
    ~Context() { if (ctx_) zuptsdk_ctx_destroy(ctx_); }
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    zuptsdk_ctx_t* raw() const noexcept { return ctx_; }
};

class Pubkey {
    zuptsdk_pubkey_t* pk_;
public:
    Pubkey() : pk_(nullptr) {}
    explicit Pubkey(zuptsdk_pubkey_t* pk) : pk_(pk) {}
    ~Pubkey() { if (pk_) zuptsdk_pubkey_destroy(pk_); }
    Pubkey(const Pubkey&) = delete;
    Pubkey& operator=(const Pubkey&) = delete;
    Pubkey(Pubkey&& o) noexcept : pk_(o.pk_) { o.pk_ = nullptr; }
    static Pubkey load(const std::string& path) {
        zuptsdk_pubkey_t* pk = nullptr;
        check(zuptsdk_pubkey_load(path.c_str(), &pk));
        return Pubkey(pk);
    }
    zuptsdk_pubkey_t* raw() const noexcept { return pk_; }
    std::array<uint8_t, 32> fingerprint() const {
        std::array<uint8_t, 32> fp{};
        check(zuptsdk_pubkey_fingerprint(pk_, fp.data()));
        return fp;
    }
};

class Privkey {
    zuptsdk_privkey_t* sk_;
public:
    Privkey() : sk_(nullptr) {}
    explicit Privkey(zuptsdk_privkey_t* sk) : sk_(sk) {}
    ~Privkey() { if (sk_) zuptsdk_privkey_destroy(sk_); }
    Privkey(const Privkey&) = delete;
    Privkey& operator=(const Privkey&) = delete;
    Privkey(Privkey&& o) noexcept : sk_(o.sk_) { o.sk_ = nullptr; }
    static Privkey load(const std::string& path) {
        zuptsdk_privkey_t* sk = nullptr;
        check(zuptsdk_privkey_load(path.c_str(), &sk));
        return Privkey(sk);
    }
    zuptsdk_privkey_t* raw() const noexcept { return sk_; }
};

class Keypair {
    zuptsdk_keypair_t* kp_;
public:
    explicit Keypair(Context& ctx) : kp_(nullptr) {
        check(zuptsdk_keypair_generate(ctx.raw(), &kp_));
    }
    ~Keypair() { if (kp_) zuptsdk_keypair_destroy(kp_); }
    Keypair(const Keypair&) = delete;
    Keypair& operator=(const Keypair&) = delete;
    void save_public(const std::string& path) const {
        check(zuptsdk_keypair_save_public(kp_, path.c_str()));
    }
    void save_private(const std::string& path) const {
        check(zuptsdk_keypair_save_private(kp_, path.c_str()));
    }
};

// Result type for encryption operations
struct EncryptResult {
    Buffer header;
    Buffer ciphertext;
};

inline EncryptResult encrypt_pq(Context& ctx, const Pubkey& pk,
                                const uint8_t* pt, std::size_t pt_sz,
                                const uint8_t* aad = nullptr, std::size_t aad_sz = 0) {
    EncryptResult r;
    check(zuptsdk_encrypt_pq(ctx.raw(), pk.raw(), pt, pt_sz, aad, aad_sz,
                             r.header.out_ptr(), r.header.out_size(),
                             r.ciphertext.out_ptr(), r.ciphertext.out_size()));
    return r;
}

inline EncryptResult encrypt_pq_v2(Context& ctx, const Pubkey& pk,
                                   int aead_id, bool forward_secret,
                                   const uint8_t* pt, std::size_t pt_sz,
                                   const uint8_t* aad = nullptr, std::size_t aad_sz = 0) {
    EncryptResult r;
    check(zuptsdk_encrypt_pq_v2(ctx.raw(), pk.raw(), aead_id, forward_secret ? 1 : 0,
                                 pt, pt_sz, aad, aad_sz,
                                 r.header.out_ptr(), r.header.out_size(),
                                 r.ciphertext.out_ptr(), r.ciphertext.out_size()));
    return r;
}

inline Buffer decrypt_pq(Context& ctx, const Privkey& sk,
                         const uint8_t* hdr, std::size_t hdr_sz,
                         const uint8_t* ct,  std::size_t ct_sz,
                         const uint8_t* aad = nullptr, std::size_t aad_sz = 0) {
    Buffer r;
    check(zuptsdk_decrypt_pq(ctx.raw(), sk.raw(), hdr, hdr_sz, ct, ct_sz, aad, aad_sz,
                              r.out_ptr(), r.out_size()));
    return r;
}

inline Buffer decrypt_pq_v2(Context& ctx, const Privkey& sk,
                            const uint8_t* hdr, std::size_t hdr_sz,
                            const uint8_t* ct,  std::size_t ct_sz,
                            const uint8_t* aad = nullptr, std::size_t aad_sz = 0) {
    Buffer r;
    check(zuptsdk_decrypt_pq_v2(ctx.raw(), sk.raw(), hdr, hdr_sz, ct, ct_sz, aad, aad_sz,
                                 r.out_ptr(), r.out_size()));
    return r;
}

// Streaming
class StreamEncrypter {
    zuptsdk_stream_state_t* st_;
    Buffer header_;
public:
    StreamEncrypter(Context& ctx, const Pubkey& pk,
                    const uint8_t* aad = nullptr, std::size_t aad_sz = 0) : st_(nullptr) {
        check(zuptsdk_stream_pq_init_encrypt(ctx.raw(), pk.raw(), aad, aad_sz,
                                              header_.out_ptr(), header_.out_size(), &st_));
    }
    ~StreamEncrypter() { if (st_) zuptsdk_stream_state_destroy(st_); }
    StreamEncrypter(const StreamEncrypter&) = delete;
    StreamEncrypter& operator=(const StreamEncrypter&) = delete;
    const Buffer& header() const noexcept { return header_; }

    std::vector<uint8_t> encrypt_chunk(const uint8_t* pt, std::size_t pt_sz, bool final_chunk) {
        std::vector<uint8_t> out(pt_sz + 21);
        std::size_t out_sz = 0;
        check(zuptsdk_stream_chunk_encrypt(st_,
            final_chunk ? ZUPTSDK_CHUNK_FINAL : ZUPTSDK_CHUNK_MESSAGE,
            pt, pt_sz, nullptr, 0, out.data(), out.size(), &out_sz));
        out.resize(out_sz);
        return out;
    }
};

class StreamDecrypter {
    zuptsdk_stream_state_t* st_;
    bool finished_ = false;
public:
    StreamDecrypter(Context& ctx, const Privkey& sk,
                    const uint8_t* hdr, std::size_t hdr_sz,
                    const uint8_t* aad = nullptr, std::size_t aad_sz = 0) : st_(nullptr) {
        check(zuptsdk_stream_pq_init_decrypt(ctx.raw(), sk.raw(), hdr, hdr_sz,
                                              aad, aad_sz, &st_));
    }
    ~StreamDecrypter() { if (st_) zuptsdk_stream_state_destroy(st_); }
    StreamDecrypter(const StreamDecrypter&) = delete;
    StreamDecrypter& operator=(const StreamDecrypter&) = delete;

    struct ChunkResult {
        std::vector<uint8_t> data;
        bool final_chunk;
    };
    ChunkResult decrypt_chunk(const uint8_t* in, std::size_t in_sz) {
        std::vector<uint8_t> out(in_sz);  // upper bound
        std::size_t out_sz = 0;
        zuptsdk_chunk_tag_t tag;
        check(zuptsdk_stream_chunk_decrypt(st_, in, in_sz, nullptr, 0,
                                            out.data(), out.size(), &out_sz, &tag));
        out.resize(out_sz);
        bool fin = (tag == ZUPTSDK_CHUNK_FINAL);
        if (fin) finished_ = true;
        return { std::move(out), fin };
    }
    bool finished() const noexcept { return finished_; }
};

inline std::string version() { return zuptsdk_version_string(); }

} // namespace zuptsdk

#endif // ZUPTSDK_HPP
