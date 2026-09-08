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
constexpr unsigned char kVersion = 1;

constexpr std::size_t kHeaderSize = sizeof(kMagic) + 1 + crypto_pwhash_SALTBYTES +
                                    8 + 8 + 8 + crypto_secretbox_NONCEBYTES;

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

}  // namespace

void Store::wipe() {
    if (passphrase_) {
        sodium_memzero(passphrase_, passphrase_len_);
        sodium_munlock(passphrase_, passphrase_len_);
        std::free(passphrase_);
        passphrase_ = nullptr;
    }
    passphrase_len_ = 0;
    if (key_) {
        sodium_memzero(key_, crypto_secretbox_KEYBYTES);
        sodium_munlock(key_, crypto_secretbox_KEYBYTES);
        std::free(key_);
        key_ = nullptr;
    }
}

void Store::derive_key(const std::string& passphrase) {
    passphrase_len_ = passphrase.size();
    passphrase_ = static_cast<unsigned char*>(std::malloc(passphrase_len_ ? passphrase_len_ : 1));
    key_ = static_cast<unsigned char*>(std::malloc(crypto_secretbox_KEYBYTES));
    if (!passphrase_ || !key_) {
        wipe();
        throw std::runtime_error("out of memory allocating key material");
    }
    if (sodium_mlock(passphrase_, passphrase_len_ ? passphrase_len_ : 1) != 0 ||
        sodium_mlock(key_, crypto_secretbox_KEYBYTES) != 0) {
        throw std::runtime_error("sodium_mlock failed: " + std::string(std::strerror(errno)));
    }
    std::memcpy(passphrase_, passphrase.data(), passphrase_len_);

    if (crypto_pwhash(key_, crypto_secretbox_KEYBYTES,
                      reinterpret_cast<const char*>(passphrase_), passphrase_len_, salt_,
                      static_cast<unsigned long long>(opslimit_),
                      static_cast<std::size_t>(memlimit_),
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::runtime_error("Argon2id key derivation failed (out of memory?)");
    }
}

void Store::persist() const {
    std::string plaintext = data_.dump();

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    std::vector<unsigned char> ciphertext(plaintext.size() + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(ciphertext.data(),
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          plaintext.size(), nonce, key_);

    std::vector<unsigned char> out;
    out.reserve(kHeaderSize + ciphertext.size());
    out.insert(out.end(), kMagic, kMagic + sizeof(kMagic));
    out.push_back(kVersion);
    out.insert(out.end(), salt_, salt_ + crypto_pwhash_SALTBYTES);
    put_u64_le(out, opslimit_);
    put_u64_le(out, memlimit_);
    put_u64_le(out, key_created_at_);
    out.insert(out.end(), nonce, nonce + sizeof(nonce));
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
    s.derive_key(passphrase);
    s.persist();
    return s;
}

Store Store::open(const std::string& path, const std::string& passphrase, std::uint64_t /*now*/) {
    ensure_sodium();
    std::vector<unsigned char> buf = read_file(path);

    if (buf.size() < sizeof(kMagic) + 1 ||
        std::memcmp(buf.data(), kMagic, sizeof(kMagic)) != 0) {
        throw std::runtime_error("not a secretov store: '" + path + "'");
    }
    if (buf[sizeof(kMagic)] != kVersion) {
        throw std::runtime_error("unsupported version: " +
                                 std::to_string(static_cast<int>(buf[sizeof(kMagic)])));
    }
    if (buf.size() < kHeaderSize + crypto_secretbox_MACBYTES) {
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
    const unsigned char* nonce = buf.data() + off;
    off += crypto_secretbox_NONCEBYTES;

    const unsigned char* ct = buf.data() + off;
    std::size_t ct_len = buf.size() - off;

    // Reject attacker-controlled KDF params before crypto_pwhash allocates on them.
    if (s.opslimit_ > crypto_pwhash_OPSLIMIT_SENSITIVE ||
        s.memlimit_ > crypto_pwhash_MEMLIMIT_SENSITIVE ||
        s.opslimit_ < crypto_pwhash_OPSLIMIT_MIN || s.memlimit_ < crypto_pwhash_MEMLIMIT_MIN) {
        throw std::runtime_error("corrupted store: implausible KDF parameters");
    }

    s.derive_key(passphrase);

    std::vector<unsigned char> plaintext(ct_len - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(plaintext.data(), ct, ct_len, nonce, s.key_) != 0) {
        throw std::runtime_error("wrong passphrase or corrupted store");
    }

    try {
        s.data_ = nlohmann::json::parse(plaintext.begin(), plaintext.end());
    } catch (const nlohmann::json::exception&) {
        throw std::runtime_error("corrupted store: decrypted payload is not valid JSON");
    }
    if (!s.data_.is_object()) {
        throw std::runtime_error("corrupted store: decrypted payload is not a JSON object");
    }
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

// Fresh salt, key derived from `pass`, re-encrypt. Shared by rotate (same
// passphrase) and change_passphrase (new one).
void Store::rekey(const unsigned char* pass, std::size_t pass_len, std::uint64_t now) {
    // Derive the new key into locals first; touch no members until it succeeds,
    // so a throw here (OOM/mlock/Argon2) leaves the store fully intact.
    unsigned char new_salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(new_salt, sizeof(new_salt));

    unsigned char* new_key = static_cast<unsigned char*>(std::malloc(crypto_secretbox_KEYBYTES));
    if (!new_key) {
        throw std::runtime_error("out of memory allocating key material");
    }
    if (sodium_mlock(new_key, crypto_secretbox_KEYBYTES) != 0) {
        std::free(new_key);
        throw std::runtime_error("sodium_mlock failed: " + std::string(std::strerror(errno)));
    }
    if (crypto_pwhash(new_key, crypto_secretbox_KEYBYTES,
                      reinterpret_cast<const char*>(pass), pass_len, new_salt,
                      static_cast<unsigned long long>(opslimit_),
                      static_cast<std::size_t>(memlimit_),
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        sodium_memzero(new_key, crypto_secretbox_KEYBYTES);
        sodium_munlock(new_key, crypto_secretbox_KEYBYTES);
        std::free(new_key);
        throw std::runtime_error("Argon2id key derivation failed (out of memory?)");
    }

    // Derivation succeeded: commit. Nothing below throws before persist.
    unsigned char* old_key = key_;
    std::memcpy(salt_, new_salt, sizeof(salt_));
    key_ = new_key;
    key_created_at_ = now;
    if (old_key) {
        sodium_memzero(old_key, crypto_secretbox_KEYBYTES);
        sodium_munlock(old_key, crypto_secretbox_KEYBYTES);
        std::free(old_key);
    }
    persist();
}

void Store::rotate(std::uint64_t now) {
    if (!passphrase_) {
        throw std::runtime_error("cannot rotate: passphrase not retained");
    }
    rekey(passphrase_, passphrase_len_, now);
}

void Store::change_passphrase(const std::string& new_passphrase, std::uint64_t now) {
    if (new_passphrase.empty()) {
        throw std::runtime_error("empty passphrase");
    }
    // Stage the new passphrase in guarded memory before rekeying, so the swap
    // after a successful persist cannot fail.
    std::size_t new_len = new_passphrase.size();
    unsigned char* new_pass = static_cast<unsigned char*>(std::malloc(new_len));
    if (!new_pass) {
        throw std::runtime_error("out of memory allocating key material");
    }
    if (sodium_mlock(new_pass, new_len) != 0) {
        std::free(new_pass);
        throw std::runtime_error("sodium_mlock failed: " + std::string(std::strerror(errno)));
    }
    std::memcpy(new_pass, new_passphrase.data(), new_len);

    try {
        rekey(new_pass, new_len, now);
    } catch (...) {
        sodium_memzero(new_pass, new_len);
        sodium_munlock(new_pass, new_len);
        std::free(new_pass);
        throw;
    }

    if (passphrase_) {
        sodium_memzero(passphrase_, passphrase_len_);
        sodium_munlock(passphrase_, passphrase_len_);
        std::free(passphrase_);
    }
    passphrase_ = new_pass;
    passphrase_len_ = new_len;
}

bool Store::passphrase_matches(const std::string& given) const {
    if (!passphrase_ || given.size() != passphrase_len_) return false;
    return sodium_memcmp(passphrase_, given.data(), passphrase_len_) == 0;
}

Store::Store(Store&& other) noexcept
    : path_(std::move(other.path_)),
      data_(std::move(other.data_)),
      passphrase_(other.passphrase_),
      passphrase_len_(other.passphrase_len_),
      key_(other.key_),
      opslimit_(other.opslimit_),
      memlimit_(other.memlimit_),
      key_created_at_(other.key_created_at_) {
    std::memcpy(salt_, other.salt_, sizeof(salt_));
    other.passphrase_ = nullptr;
    other.passphrase_len_ = 0;
    other.key_ = nullptr;
}

Store& Store::operator=(Store&& other) noexcept {
    if (this != &other) {
        wipe();
        path_ = std::move(other.path_);
        data_ = std::move(other.data_);
        passphrase_ = other.passphrase_;
        passphrase_len_ = other.passphrase_len_;
        key_ = other.key_;
        std::memcpy(salt_, other.salt_, sizeof(salt_));
        opslimit_ = other.opslimit_;
        memlimit_ = other.memlimit_;
        key_created_at_ = other.key_created_at_;
        other.passphrase_ = nullptr;
        other.passphrase_len_ = 0;
        other.key_ = nullptr;
    }
    return *this;
}

Store::~Store() { wipe(); }

}  // namespace secretov
