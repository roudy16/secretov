#include "store.hpp"

#include <fcntl.h>
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

std::vector<unsigned char> read_file(const std::string& path) {
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        throw std::runtime_error("open '" + path + "' for read: " + std::strerror(errno));
    }
    std::vector<unsigned char> buf;
    unsigned char chunk[4096];
    for (;;) {
        ssize_t n = ::read(fd, chunk, sizeof(chunk));
        if (n < 0) {
            int e = errno;
            ::close(fd);
            throw std::runtime_error("read '" + path + "': " + std::strerror(e));
        }
        if (n == 0) break;
        buf.insert(buf.end(), chunk, chunk + n);
    }
    ::close(fd);
    return buf;
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
        wrap_key = derive_kdf_key(passphrase, salt_, opslimit_, memlimit_);
    } catch (...) {
        free_guarded(data_key, crypto_secretbox_KEYBYTES);
        throw;
    }
    if (crypto_secretbox_open_easy(data_key, wrapped_key_, sizeof(wrapped_key_), wrap_nonce_,
                                   wrap_key) != 0) {
        free_guarded(wrap_key, crypto_secretbox_KEYBYTES);
        free_guarded(data_key, crypto_secretbox_KEYBYTES);
        throw std::runtime_error(fail_msg);
    }
    return {wrap_key, data_key};
}

void Store::persist() const {
    std::string plaintext = data_.dump();

    unsigned char payload_nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(payload_nonce, sizeof(payload_nonce));

    std::vector<unsigned char> ciphertext(plaintext.size() + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(ciphertext.data(),
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          plaintext.size(), payload_nonce, key_);

    std::vector<unsigned char> out;
    out.reserve(kHeaderSizeV2 + ciphertext.size());
    out.insert(out.end(), kMagic, kMagic + sizeof(kMagic));
    out.push_back(kVersion2);
    out.insert(out.end(), salt_, salt_ + crypto_pwhash_SALTBYTES);
    put_u64_le(out, opslimit_);
    put_u64_le(out, memlimit_);
    put_u64_le(out, key_created_at_);
    out.insert(out.end(), wrap_nonce_, wrap_nonce_ + sizeof(wrap_nonce_));
    out.insert(out.end(), wrapped_key_, wrapped_key_ + sizeof(wrapped_key_));
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
    randombytes_buf(s.salt_, sizeof(s.salt_));
    s.opslimit_ = crypto_pwhash_OPSLIMIT_MODERATE;
    s.memlimit_ = crypto_pwhash_MEMLIMIT_MODERATE;
    s.key_created_at_ = now;

    unsigned char* data_key = alloc_guarded(crypto_secretbox_KEYBYTES);
    unsigned char* wrap_key = nullptr;
    try {
        wrap_key = derive_kdf_key(passphrase, s.salt_, s.opslimit_, s.memlimit_);
    } catch (...) {
        free_guarded(data_key, crypto_secretbox_KEYBYTES);
        throw;
    }
    randombytes_buf(data_key, crypto_secretbox_KEYBYTES);
    randombytes_buf(s.wrap_nonce_, sizeof(s.wrap_nonce_));
    crypto_secretbox_easy(s.wrapped_key_, data_key, crypto_secretbox_KEYBYTES, s.wrap_nonce_,
                          wrap_key);
    free_guarded(wrap_key, crypto_secretbox_KEYBYTES);

    s.key_ = data_key;
    s.persist();
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
    std::vector<unsigned char> buf = read_file(path);

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
            decoded = decode_v1(buf, passphrase, s.salt_, s.opslimit_, s.memlimit_,
                                s.key_created_at_);
        } catch (...) {
            free_guarded(data_key, crypto_secretbox_KEYBYTES);
            throw;
        }
        s.data_ = std::move(decoded.data);

        // Migrate: mint a fresh data key, wrap it under the same
        // passphrase-derived key with a fresh wrap nonce; salt/params/
        // key_created_at are kept.
        randombytes_buf(data_key, crypto_secretbox_KEYBYTES);
        randombytes_buf(s.wrap_nonce_, sizeof(s.wrap_nonce_));
        crypto_secretbox_easy(s.wrapped_key_, data_key, crypto_secretbox_KEYBYTES, s.wrap_nonce_,
                              decoded.key);
        free_guarded(decoded.key, crypto_secretbox_KEYBYTES);

        s.key_ = data_key;
        s.persist();
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
    std::memcpy(s.salt_, buf.data() + off, crypto_pwhash_SALTBYTES);
    off += crypto_pwhash_SALTBYTES;
    s.opslimit_ = get_u64_le(buf.data() + off);
    off += 8;
    s.memlimit_ = get_u64_le(buf.data() + off);
    off += 8;
    s.key_created_at_ = get_u64_le(buf.data() + off);
    off += 8;
    std::memcpy(s.wrap_nonce_, buf.data() + off, sizeof(s.wrap_nonce_));
    off += sizeof(s.wrap_nonce_);
    std::memcpy(s.wrapped_key_, buf.data() + off, sizeof(s.wrapped_key_));
    off += sizeof(s.wrapped_key_);
    const unsigned char* payload_nonce = buf.data() + off;
    off += crypto_secretbox_NONCEBYTES;

    const unsigned char* ct = buf.data() + off;
    std::size_t ct_len = buf.size() - off;

    check_kdf_params(s.opslimit_, s.memlimit_);

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
    auto it = data_.find(key);
    bool existed = it != data_.end();
    std::string prev = existed ? it->get<std::string>() : std::string();
    data_[key] = value;
    try {
        persist();
    } catch (...) {
        if (existed) {
            data_[key] = prev;
        } else {
            data_.erase(key);
        }
        throw;
    }
}

bool Store::remove(const std::string& key) {
    auto it = data_.find(key);
    if (it == data_.end()) return false;
    std::string prev = it->get<std::string>();
    data_.erase(it);
    try {
        persist();
    } catch (...) {
        data_[key] = prev;
        throw;
    }
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

void Store::rotate(const std::string& passphrase, std::uint64_t now) {
    // Everything into locals first; only after it all succeeds do we touch
    // members, so a throw here leaves the store fully intact.
    unsigned char* new_data_key = alloc_guarded(crypto_secretbox_KEYBYTES);
    Unwrapped keys;
    try {
        keys = unwrap(passphrase, "wrong passphrase");  // proves the passphrase
    } catch (...) {
        free_guarded(new_data_key, crypto_secretbox_KEYBYTES);
        throw;
    }
    free_guarded(keys.data_key, crypto_secretbox_KEYBYTES);  // we already hold it in key_
    unsigned char* wrap_key = keys.wrap_key;

    // Mint a fresh data key and wrap it under the same wrapping key (same
    // salt/params, fresh wrap nonce).
    randombytes_buf(new_data_key, crypto_secretbox_KEYBYTES);
    unsigned char new_wrap_nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(new_wrap_nonce, sizeof(new_wrap_nonce));
    unsigned char new_wrapped_key[crypto_secretbox_KEYBYTES + crypto_secretbox_MACBYTES];
    crypto_secretbox_easy(new_wrapped_key, new_data_key, crypto_secretbox_KEYBYTES,
                          new_wrap_nonce, wrap_key);
    free_guarded(wrap_key, crypto_secretbox_KEYBYTES);

    // Commit: nothing below throws before persist except persist itself,
    // and persist leaves the object in a well-defined (new) state either way.
    unsigned char* old_key = key_;
    key_ = new_data_key;
    std::memcpy(wrap_nonce_, new_wrap_nonce, sizeof(wrap_nonce_));
    std::memcpy(wrapped_key_, new_wrapped_key, sizeof(wrapped_key_));
    key_created_at_ = now;
    free_guarded(old_key, crypto_secretbox_KEYBYTES);
    persist();
}

void Store::change_passphrase(const std::string& old_pass, const std::string& new_pass) {
    if (new_pass.empty()) {
        throw std::runtime_error("empty passphrase");
    }
    // Verify the old passphrase against the current wrapped blob.
    Unwrapped check = unwrap(old_pass, "wrong passphrase");
    free_guarded(check.wrap_key, crypto_secretbox_KEYBYTES);
    free_guarded(check.data_key, crypto_secretbox_KEYBYTES);

    // Fresh salt, wrap the EXISTING data key under a key derived from the
    // new passphrase. Locals first; nothing below throws before persist.
    unsigned char new_salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(new_salt, sizeof(new_salt));
    unsigned char* new_wrap_key = derive_kdf_key(new_pass, new_salt, opslimit_, memlimit_);
    unsigned char new_wrap_nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(new_wrap_nonce, sizeof(new_wrap_nonce));
    unsigned char new_wrapped_key[crypto_secretbox_KEYBYTES + crypto_secretbox_MACBYTES];
    crypto_secretbox_easy(new_wrapped_key, key_, crypto_secretbox_KEYBYTES, new_wrap_nonce,
                          new_wrap_key);
    free_guarded(new_wrap_key, crypto_secretbox_KEYBYTES);

    std::memcpy(salt_, new_salt, sizeof(salt_));
    std::memcpy(wrap_nonce_, new_wrap_nonce, sizeof(wrap_nonce_));
    std::memcpy(wrapped_key_, new_wrapped_key, sizeof(wrapped_key_));
    // key_created_at_ unchanged: the data key itself did not change.
    persist();
}

Store::Store(Store&& other) noexcept
    : path_(std::move(other.path_)),
      data_(std::move(other.data_)),
      key_(other.key_),
      opslimit_(other.opslimit_),
      memlimit_(other.memlimit_),
      key_created_at_(other.key_created_at_) {
    std::memcpy(salt_, other.salt_, sizeof(salt_));
    std::memcpy(wrap_nonce_, other.wrap_nonce_, sizeof(wrap_nonce_));
    std::memcpy(wrapped_key_, other.wrapped_key_, sizeof(wrapped_key_));
    other.key_ = nullptr;
}

Store& Store::operator=(Store&& other) noexcept {
    if (this != &other) {
        wipe();
        path_ = std::move(other.path_);
        data_ = std::move(other.data_);
        key_ = other.key_;
        std::memcpy(salt_, other.salt_, sizeof(salt_));
        std::memcpy(wrap_nonce_, other.wrap_nonce_, sizeof(wrap_nonce_));
        std::memcpy(wrapped_key_, other.wrapped_key_, sizeof(wrapped_key_));
        opslimit_ = other.opslimit_;
        memlimit_ = other.memlimit_;
        key_created_at_ = other.key_created_at_;
        other.key_ = nullptr;
    }
    return *this;
}

Store::~Store() { wipe(); }

}  // namespace secretov
