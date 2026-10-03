#include "store.hpp"

#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "paths.hpp"

namespace secretov {

namespace {

constexpr unsigned char kMagic[4] = {'S', 'C', 'T', 'V'};
constexpr unsigned char kVersion1 = 1;
constexpr unsigned char kVersion2 = 2;

// Used at create, and by passwd to upgrade a store made with weaker params.
constexpr std::uint64_t kDefaultOpslimit = crypto_pwhash_OPSLIMIT_MODERATE;
constexpr std::uint64_t kDefaultMemlimit = crypto_pwhash_MEMLIMIT_MODERATE;

constexpr std::size_t kHeaderSizeV1 = sizeof(kMagic) + 1 + crypto_pwhash_SALTBYTES + 8 + 8 + 8 +
                                      crypto_secretbox_NONCEBYTES;
constexpr std::size_t kHeaderSizeV2 = sizeof(kMagic) + 1 + crypto_pwhash_SALTBYTES + 8 + 8 + 8 +
                                      crypto_secretbox_NONCEBYTES +
                                      (crypto_secretbox_KEYBYTES + crypto_secretbox_MACBYTES) +
                                      crypto_secretbox_NONCEBYTES;

void ensure_sodium() {
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium initialization failed");
    }
}

void put_u64_le(std::vector<unsigned char>& out, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<unsigned char>(v >> (8 * i)));
    }
}

std::uint64_t get_u64_le(const unsigned char* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<std::uint64_t>(p[i]) << (8 * i);
    }
    return v;
}

// Reject attacker-controlled KDF params before crypto_pwhash allocates on them.
void check_kdf_params(std::uint64_t opslimit, std::uint64_t memlimit) {
    if (opslimit > crypto_pwhash_OPSLIMIT_SENSITIVE || memlimit > crypto_pwhash_MEMLIMIT_SENSITIVE ||
        opslimit < crypto_pwhash_OPSLIMIT_MIN || memlimit < crypto_pwhash_MEMLIMIT_MIN) {
        throw std::runtime_error("corrupted store: implausible KDF parameters");
    }
}

unsigned char* alloc_guarded(std::size_t len) {
    unsigned char* p = static_cast<unsigned char*>(std::malloc(len ? len : 1));
    if (!p) {
        throw std::runtime_error("out of memory allocating key material");
    }
    if (sodium_mlock(p, len ? len : 1) != 0) {
        std::free(p);
        throw std::runtime_error("sodium_mlock failed: " + std::string(std::strerror(errno)));
    }
    return p;
}

void free_guarded(unsigned char* p, std::size_t len) {
    if (!p) return;
    sodium_memzero(p, len ? len : 1);
    sodium_munlock(p, len ? len : 1);
    std::free(p);
}

// Argon2id(passphrase, salt, opslimit, memlimit) into a fresh mlock'd buffer.
// Caller owns the result and must free_guarded() it.
unsigned char* derive_kdf_key(const std::string& passphrase, const unsigned char* salt,
                              std::uint64_t opslimit, std::uint64_t memlimit) {
    unsigned char* key = alloc_guarded(crypto_secretbox_KEYBYTES);
    if (crypto_pwhash(key, crypto_secretbox_KEYBYTES, passphrase.data(), passphrase.size(), salt,
                      static_cast<unsigned long long>(opslimit),
                      static_cast<std::size_t>(memlimit), crypto_pwhash_ALG_ARGON2ID13) != 0) {
        free_guarded(key, crypto_secretbox_KEYBYTES);
        throw std::runtime_error("Argon2id key derivation failed (out of memory?)");
    }
    return key;
}

}  // namespace

void Store::wipe() {
    free_guarded(key_, crypto_secretbox_KEYBYTES);
    key_ = nullptr;
}

// Derives the wrapping key from `passphrase` (store's own salt and KDF
// params) and proves it by unwrapping the stored data key blob. One Argon2id
// call serves both verification and whatever the caller does next. Both
// returned buffers are guarded; the caller frees each. `fail_msg` is thrown
// on MAC failure so open() and rotate()/change_passphrase() can report
// different messages for the same check.
Store::Unwrapped Store::unwrap(const std::string& passphrase, const char* fail_msg) const {
    unsigned char* data_key = alloc_guarded(crypto_secretbox_KEYBYTES);
    unsigned char* wrap_key = nullptr;
    try {
        wrap_key = derive_kdf_key(passphrase, env_.salt, env_.opslimit, env_.memlimit);
    } catch (...) {
        free_guarded(data_key, crypto_secretbox_KEYBYTES);
        throw;
    }
    if (crypto_secretbox_open_easy(data_key, env_.wrapped_key, sizeof(env_.wrapped_key),
                                   env_.wrap_nonce, wrap_key) != 0) {
        free_guarded(wrap_key, crypto_secretbox_KEYBYTES);
        free_guarded(data_key, crypto_secretbox_KEYBYTES);
        throw std::runtime_error(fail_msg);
    }
    return {wrap_key, data_key};
}

void Store::mint_data_key(unsigned char* data_key, const unsigned char* wrap_key,
                          Envelope& envelope) {
    randombytes_buf(data_key, crypto_secretbox_KEYBYTES);
    randombytes_buf(envelope.wrap_nonce, sizeof(envelope.wrap_nonce));
    crypto_secretbox_easy(envelope.wrapped_key, data_key, crypto_secretbox_KEYBYTES,
                          envelope.wrap_nonce, wrap_key);
}

// Encrypts `data` under `data_key` and writes the whole file with `envelope`
// as its header. Callers that change the map, the key, or the envelope pass
// candidates and adopt them only after this returns, so a failed write never
// leaves memory ahead of disk.
void Store::persist(const nlohmann::json& data, const unsigned char* data_key,
                    const Envelope& envelope) const {
    std::string plaintext = data.dump();

    unsigned char payload_nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(payload_nonce, sizeof(payload_nonce));

    std::vector<unsigned char> ciphertext(plaintext.size() + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(ciphertext.data(),
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          plaintext.size(), payload_nonce, data_key);

    std::vector<unsigned char> out;
    out.reserve(kHeaderSizeV2 + ciphertext.size());
    out.insert(out.end(), kMagic, kMagic + sizeof(kMagic));
    out.push_back(kVersion2);
    out.insert(out.end(), envelope.salt, envelope.salt + sizeof(envelope.salt));
    put_u64_le(out, envelope.opslimit);
    put_u64_le(out, envelope.memlimit);
    put_u64_le(out, envelope.key_created_at);
    out.insert(out.end(), envelope.wrap_nonce, envelope.wrap_nonce + sizeof(envelope.wrap_nonce));
    out.insert(out.end(), envelope.wrapped_key,
               envelope.wrapped_key + sizeof(envelope.wrapped_key));
    out.insert(out.end(), payload_nonce, payload_nonce + sizeof(payload_nonce));
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());

    write_file_atomic(path_, std::string(out.begin(), out.end()), 0600);
}

Store Store::create(const std::string& path, const std::string& passphrase, std::uint64_t now) {
    ensure_sodium();
    if (::access(path.c_str(), F_OK) == 0) {
        throw std::runtime_error("store already exists: '" + path + "'");
    }

    Store s;
    s.path_ = path;
    randombytes_buf(s.env_.salt, sizeof(s.env_.salt));
    s.env_.opslimit = kDefaultOpslimit;
    s.env_.memlimit = kDefaultMemlimit;
    s.env_.key_created_at = now;

    unsigned char* data_key = alloc_guarded(crypto_secretbox_KEYBYTES);
    unsigned char* wrap_key = nullptr;
    try {
        wrap_key = derive_kdf_key(passphrase, s.env_.salt, s.env_.opslimit, s.env_.memlimit);
    } catch (...) {
        free_guarded(data_key, crypto_secretbox_KEYBYTES);
        throw;
    }
    mint_data_key(data_key, wrap_key, s.env_);
    free_guarded(wrap_key, crypto_secretbox_KEYBYTES);

    s.key_ = data_key;
    s.persist(s.data_, s.key_, s.env_);
    return s;
}

namespace {

// Parses a version-1 header (no envelope), decrypts the payload directly
// with the passphrase-derived key, and returns that key (guarded, caller
// frees) along with the parsed JSON. Used only for one-way migration.
struct V1Decoded {
    unsigned char* key = nullptr;  // crypto_secretbox_KEYBYTES, guarded
    nlohmann::json data;
};

V1Decoded decode_v1(const std::vector<unsigned char>& buf, const std::string& passphrase,
                    unsigned char (&salt_out)[crypto_pwhash_SALTBYTES],
                    std::uint64_t& opslimit_out, std::uint64_t& memlimit_out,
                    std::uint64_t& key_created_at_out) {
    if (buf.size() < kHeaderSizeV1 + crypto_secretbox_MACBYTES) {
        throw std::runtime_error("corrupted store: truncated header or ciphertext");
    }
    std::size_t off = sizeof(kMagic) + 1;
    std::memcpy(salt_out, buf.data() + off, crypto_pwhash_SALTBYTES);
    off += crypto_pwhash_SALTBYTES;
    opslimit_out = get_u64_le(buf.data() + off);
    off += 8;
    memlimit_out = get_u64_le(buf.data() + off);
    off += 8;
    key_created_at_out = get_u64_le(buf.data() + off);
    off += 8;
    const unsigned char* nonce = buf.data() + off;
    off += crypto_secretbox_NONCEBYTES;
    const unsigned char* ct = buf.data() + off;
    std::size_t ct_len = buf.size() - off;

    check_kdf_params(opslimit_out, memlimit_out);

    unsigned char* key = derive_kdf_key(passphrase, salt_out, opslimit_out, memlimit_out);

    std::vector<unsigned char> plaintext(ct_len - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(plaintext.data(), ct, ct_len, nonce, key) != 0) {
        free_guarded(key, crypto_secretbox_KEYBYTES);
        throw std::runtime_error("wrong passphrase or corrupted store");
    }

    nlohmann::json data;
    try {
        data = nlohmann::json::parse(plaintext.begin(), plaintext.end());
    } catch (const nlohmann::json::exception&) {
        free_guarded(key, crypto_secretbox_KEYBYTES);
        throw std::runtime_error("corrupted store: decrypted payload is not valid JSON");
    }
    if (!data.is_object()) {
        free_guarded(key, crypto_secretbox_KEYBYTES);
        throw std::runtime_error("corrupted store: decrypted payload is not a JSON object");
    }
    return {key, std::move(data)};
}

}  // namespace

Store Store::open(const std::string& path, const std::string& passphrase) {
    ensure_sodium();
    std::string raw = read_file_string(path);
    std::vector<unsigned char> buf(raw.begin(), raw.end());

    if (buf.size() < sizeof(kMagic) + 1 ||
        std::memcmp(buf.data(), kMagic, sizeof(kMagic)) != 0) {
        throw std::runtime_error("not a secretov store: '" + path + "'");
    }
    unsigned char version = buf[sizeof(kMagic)];

    if (version == kVersion1) {
        Store s;
        s.path_ = path;
        unsigned char* data_key = alloc_guarded(crypto_secretbox_KEYBYTES);
        V1Decoded decoded;
        try {
            decoded = decode_v1(buf, passphrase, s.env_.salt, s.env_.opslimit, s.env_.memlimit,
                                s.env_.key_created_at);
        } catch (...) {
            free_guarded(data_key, crypto_secretbox_KEYBYTES);
            throw;
        }
        s.data_ = std::move(decoded.data);

        // Migrate: mint a fresh data key, wrap it under the same
        // passphrase-derived key with a fresh wrap nonce; salt/params/
        // key_created_at are kept.
        mint_data_key(data_key, decoded.key, s.env_);
        free_guarded(decoded.key, crypto_secretbox_KEYBYTES);

        s.key_ = data_key;
        s.persist(s.data_, s.key_, s.env_);
        return s;
    }

    if (version != kVersion2) {
        throw std::runtime_error("unsupported version: " + std::to_string(static_cast<int>(version)));
    }
    if (buf.size() < kHeaderSizeV2 + crypto_secretbox_MACBYTES) {
        throw std::runtime_error("corrupted store: truncated header or ciphertext: '" + path + "'");
    }

    Store s;
    s.path_ = path;
    std::size_t off = sizeof(kMagic) + 1;
    std::memcpy(s.env_.salt, buf.data() + off, sizeof(s.env_.salt));
    off += sizeof(s.env_.salt);
    s.env_.opslimit = get_u64_le(buf.data() + off);
    off += 8;
    s.env_.memlimit = get_u64_le(buf.data() + off);
    off += 8;
    s.env_.key_created_at = get_u64_le(buf.data() + off);
    off += 8;
    std::memcpy(s.env_.wrap_nonce, buf.data() + off, sizeof(s.env_.wrap_nonce));
    off += sizeof(s.env_.wrap_nonce);
    std::memcpy(s.env_.wrapped_key, buf.data() + off, sizeof(s.env_.wrapped_key));
    off += sizeof(s.env_.wrapped_key);
    const unsigned char* payload_nonce = buf.data() + off;
    off += crypto_secretbox_NONCEBYTES;

    const unsigned char* ct = buf.data() + off;
    std::size_t ct_len = buf.size() - off;

    check_kdf_params(s.env_.opslimit, s.env_.memlimit);

    Unwrapped keys = s.unwrap(passphrase, "wrong passphrase or corrupted store");
    free_guarded(keys.wrap_key, crypto_secretbox_KEYBYTES);
    unsigned char* data_key = keys.data_key;

    std::vector<unsigned char> plaintext(ct_len - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(plaintext.data(), ct, ct_len, payload_nonce, data_key) != 0) {
        free_guarded(data_key, crypto_secretbox_KEYBYTES);
        throw std::runtime_error("wrong passphrase or corrupted store");
    }

    try {
        s.data_ = nlohmann::json::parse(plaintext.begin(), plaintext.end());
    } catch (const nlohmann::json::exception&) {
        free_guarded(data_key, crypto_secretbox_KEYBYTES);
        throw std::runtime_error("corrupted store: decrypted payload is not valid JSON");
    }
    if (!s.data_.is_object()) {
        free_guarded(data_key, crypto_secretbox_KEYBYTES);
        throw std::runtime_error("corrupted store: decrypted payload is not a JSON object");
    }

    s.key_ = data_key;
    return s;
}

std::optional<std::string> Store::get(const std::string& key) const {
    auto it = data_.find(key);
    if (it == data_.end()) return std::nullopt;
    return it->get<std::string>();
}

void Store::set(const std::string& key, const std::string& value) {
    nlohmann::json next = data_;
    next[key] = value;
    persist(next, key_, env_);
    data_ = std::move(next);
}

bool Store::remove(const std::string& key) {
    if (!data_.contains(key)) return false;
    nlohmann::json next = data_;
    next.erase(key);
    persist(next, key_, env_);
    data_ = std::move(next);
    return true;
}

std::vector<std::string> Store::list() const {
    std::vector<std::string> keys;
    for (auto it = data_.begin(); it != data_.end(); ++it) {
        keys.push_back(it.key());
    }
    std::sort(keys.begin(), keys.end());
    return keys;
}

std::map<std::string, std::string> Store::get_prefix(const std::string& prefix) const {
    std::map<std::string, std::string> out;
    for (auto it = data_.begin(); it != data_.end(); ++it) {
        if (it.key().compare(0, prefix.size(), prefix) == 0) {
            out[it.key()] = it->get<std::string>();
        }
    }
    return out;
}

void Store::commit_new_key(unsigned char* new_data_key, const Envelope& next) {
    try {
        persist(data_, new_data_key, next);
    } catch (...) {
        free_guarded(new_data_key, crypto_secretbox_KEYBYTES);
        throw;
    }
    free_guarded(key_, crypto_secretbox_KEYBYTES);
    key_ = new_data_key;
    env_ = next;
}

void Store::rotate(const std::string& passphrase, std::uint64_t now) {
    unsigned char* new_data_key = alloc_guarded(crypto_secretbox_KEYBYTES);
    Unwrapped keys;
    try {
        keys = unwrap(passphrase, "wrong passphrase");  // proves the passphrase
    } catch (...) {
        free_guarded(new_data_key, crypto_secretbox_KEYBYTES);
        throw;
    }
    free_guarded(keys.data_key, crypto_secretbox_KEYBYTES);  // we already hold it in key_

    // Same wrapping key (salt/params unchanged); fresh data key and wrap nonce.
    Envelope next = env_;
    next.key_created_at = now;
    mint_data_key(new_data_key, keys.wrap_key, next);
    free_guarded(keys.wrap_key, crypto_secretbox_KEYBYTES);
    commit_new_key(new_data_key, next);
}

void Store::change_passphrase(const std::string& old_pass, const std::string& new_pass,
                              std::uint64_t now) {
    if (new_pass.empty()) {
        throw std::runtime_error("empty passphrase");
    }
    Unwrapped check = unwrap(old_pass, "wrong passphrase");
    free_guarded(check.wrap_key, crypto_secretbox_KEYBYTES);
    free_guarded(check.data_key, crypto_secretbox_KEYBYTES);

    // A fresh data key, not a re-wrap of the old one: an old copy of the file
    // plus the old passphrase must not unwrap the key protecting later writes.
    // At least the current default KDF params, so passwd upgrades a store made
    // with weaker ones and never downgrades a stronger one.
    Envelope next;
    randombytes_buf(next.salt, sizeof(next.salt));
    next.opslimit = std::max<std::uint64_t>(env_.opslimit, kDefaultOpslimit);
    next.memlimit = std::max<std::uint64_t>(env_.memlimit, kDefaultMemlimit);
    next.key_created_at = now;
    unsigned char* new_data_key = alloc_guarded(crypto_secretbox_KEYBYTES);
    unsigned char* new_wrap_key = nullptr;
    try {
        new_wrap_key = derive_kdf_key(new_pass, next.salt, next.opslimit, next.memlimit);
    } catch (...) {
        free_guarded(new_data_key, crypto_secretbox_KEYBYTES);
        throw;
    }
    mint_data_key(new_data_key, new_wrap_key, next);
    free_guarded(new_wrap_key, crypto_secretbox_KEYBYTES);
    commit_new_key(new_data_key, next);
}

Store::Store(Store&& other) noexcept
    : path_(std::move(other.path_)),
      data_(std::move(other.data_)),
      key_(other.key_),
      env_(other.env_) {
    other.key_ = nullptr;
}

Store& Store::operator=(Store&& other) noexcept {
    if (this != &other) {
        wipe();
        path_ = std::move(other.path_);
        data_ = std::move(other.data_);
        key_ = other.key_;
        env_ = other.env_;
        other.key_ = nullptr;
    }
    return *this;
}

Store::~Store() { wipe(); }

}  // namespace secretov
