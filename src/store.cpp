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

// magic, version, salt, opslimit, memlimit, key_created_at
constexpr std::size_t kCommonHeaderSize = sizeof(kMagic) + 1 + crypto_pwhash_SALTBYTES + 8 + 8 + 8;
constexpr std::size_t kHeaderSizeV1 = kCommonHeaderSize + crypto_secretbox_NONCEBYTES;
constexpr std::size_t kHeaderSizeV2 = kCommonHeaderSize + crypto_secretbox_NONCEBYTES +
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

GuardedKey alloc_guarded() {
    auto* key = static_cast<unsigned char*>(std::malloc(crypto_secretbox_KEYBYTES));
    if (!key) {
        throw std::runtime_error("out of memory allocating key material");
    }
    if (sodium_mlock(key, crypto_secretbox_KEYBYTES) != 0) {
        std::free(key);
        throw std::runtime_error("sodium_mlock failed: " + std::string(std::strerror(errno)));
    }
    return GuardedKey(key);
}

// Argon2id(passphrase, salt, opslimit, memlimit) into a fresh guarded buffer.
GuardedKey derive_kdf_key(const std::string& passphrase, const unsigned char* salt,
                          std::uint64_t opslimit, std::uint64_t memlimit) {
    GuardedKey key = alloc_guarded();
    if (crypto_pwhash(key.get(), crypto_secretbox_KEYBYTES, passphrase.data(), passphrase.size(),
                      salt, static_cast<unsigned long long>(opslimit),
                      static_cast<std::size_t>(memlimit), crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::runtime_error("Argon2id key derivation failed (out of memory?)");
    }
    return key;
}

// Decrypts and validates a payload; v1 and v2 share this after their headers.
nlohmann::json decrypt_payload(const unsigned char* ciphertext, std::size_t ciphertext_len,
                               const unsigned char* nonce, const unsigned char* key) {
    std::vector<unsigned char> plaintext(ciphertext_len - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(plaintext.data(), ciphertext, ciphertext_len, nonce, key) != 0) {
        throw std::runtime_error("wrong passphrase or corrupted store");
    }
    nlohmann::json data;
    try {
        data = nlohmann::json::parse(plaintext.begin(), plaintext.end());
    } catch (const nlohmann::json::exception&) {
        throw std::runtime_error("corrupted store: decrypted payload is not valid JSON");
    }
    if (!data.is_object()) {
        throw std::runtime_error("corrupted store: decrypted payload is not a JSON object");
    }
    return data;
}

}  // namespace

void GuardedFree::operator()(unsigned char* key) const noexcept {
    sodium_memzero(key, crypto_secretbox_KEYBYTES);
    sodium_munlock(key, crypto_secretbox_KEYBYTES);
    std::free(key);
}

// Derives the wrapping key from `passphrase` (store's own salt and KDF
// params) and proves it by unwrapping the stored data key blob. One Argon2id
// call serves both verification and whatever the caller does next.
// `fail_msg` is thrown on MAC failure so open() and rotate()/
// change_passphrase() can report different messages for the same check.
Store::Unwrapped Store::unwrap(const std::string& passphrase, const char* fail_msg) const {
    Unwrapped keys;
    keys.data_key = alloc_guarded();
    keys.wrap_key = derive_kdf_key(passphrase, env_.salt, env_.opslimit, env_.memlimit);
    if (crypto_secretbox_open_easy(keys.data_key.get(), env_.wrapped_key,
                                   sizeof(env_.wrapped_key), env_.wrap_nonce,
                                   keys.wrap_key.get()) != 0) {
        throw std::runtime_error(fail_msg);
    }
    return keys;
}

void Store::mint_data_key(unsigned char* data_key, const unsigned char* wrap_key,
                          Envelope& envelope) {
    randombytes_buf(data_key, crypto_secretbox_KEYBYTES);
    randombytes_buf(envelope.wrap_nonce, sizeof(envelope.wrap_nonce));
    crypto_secretbox_easy(envelope.wrapped_key, data_key, crypto_secretbox_KEYBYTES,
                          envelope.wrap_nonce, wrap_key);
}

GuardedKey Store::mint_fresh_envelope(const std::string& passphrase, std::uint64_t opslimit,
                                      std::uint64_t memlimit, std::uint64_t now,
                                      Envelope& envelope) {
    randombytes_buf(envelope.salt, sizeof(envelope.salt));
    envelope.opslimit = opslimit;
    envelope.memlimit = memlimit;
    envelope.key_created_at = now;
    GuardedKey wrap_key = derive_kdf_key(passphrase, envelope.salt, opslimit, memlimit);
    GuardedKey data_key = alloc_guarded();
    mint_data_key(data_key.get(), wrap_key.get(), envelope);
    return data_key;
}

std::size_t Store::read_common_header(const std::vector<unsigned char>& buf, Envelope& envelope) {
    std::size_t offset = sizeof(kMagic) + 1;
    std::memcpy(envelope.salt, buf.data() + offset, sizeof(envelope.salt));
    offset += sizeof(envelope.salt);
    envelope.opslimit = get_u64_le(buf.data() + offset);
    offset += 8;
    envelope.memlimit = get_u64_le(buf.data() + offset);
    offset += 8;
    envelope.key_created_at = get_u64_le(buf.data() + offset);
    offset += 8;
    check_kdf_params(envelope.opslimit, envelope.memlimit);
    return offset;
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
    s.key_ = mint_fresh_envelope(passphrase, kDefaultOpslimit, kDefaultMemlimit, now, s.env_);
    s.persist(s.data_, s.key_.get(), s.env_);
    return s;
}

Store Store::open(const std::string& path, const std::string& passphrase) {
    ensure_sodium();
    std::string raw = read_file_string(path);
    std::vector<unsigned char> buf(raw.begin(), raw.end());

    if (buf.size() < sizeof(kMagic) + 1 ||
        std::memcmp(buf.data(), kMagic, sizeof(kMagic)) != 0) {
        throw std::runtime_error("not a secretov store: '" + path + "'");
    }
    unsigned char version = buf[sizeof(kMagic)];

    Store s;
    s.path_ = path;

    if (version == kVersion1) {
        if (buf.size() < kHeaderSizeV1 + crypto_secretbox_MACBYTES) {
            throw std::runtime_error("corrupted store: truncated header or ciphertext");
        }
        std::size_t offset = read_common_header(buf, s.env_);
        const unsigned char* payload_nonce = buf.data() + offset;
        offset += crypto_secretbox_NONCEBYTES;

        // Version 1 has no envelope: the passphrase-derived key encrypts the
        // payload directly.
        GuardedKey wrap_key =
            derive_kdf_key(passphrase, s.env_.salt, s.env_.opslimit, s.env_.memlimit);
        s.data_ = decrypt_payload(buf.data() + offset, buf.size() - offset, payload_nonce,
                                  wrap_key.get());

        // Migrate: mint a fresh data key, wrap it under the same
        // passphrase-derived key with a fresh wrap nonce; salt/params/
        // key_created_at are kept.
        s.key_ = alloc_guarded();
        mint_data_key(s.key_.get(), wrap_key.get(), s.env_);
        wrap_key.reset();
        s.persist(s.data_, s.key_.get(), s.env_);
        return s;
    }

    if (version != kVersion2) {
        throw std::runtime_error("unsupported version: " + std::to_string(static_cast<int>(version)));
    }
    if (buf.size() < kHeaderSizeV2 + crypto_secretbox_MACBYTES) {
        throw std::runtime_error("corrupted store: truncated header or ciphertext: '" + path + "'");
    }

    std::size_t offset = read_common_header(buf, s.env_);
    std::memcpy(s.env_.wrap_nonce, buf.data() + offset, sizeof(s.env_.wrap_nonce));
    offset += sizeof(s.env_.wrap_nonce);
    std::memcpy(s.env_.wrapped_key, buf.data() + offset, sizeof(s.env_.wrapped_key));
    offset += sizeof(s.env_.wrapped_key);
    const unsigned char* payload_nonce = buf.data() + offset;
    offset += crypto_secretbox_NONCEBYTES;

    Unwrapped keys = s.unwrap(passphrase, "wrong passphrase or corrupted store");
    keys.wrap_key.reset();
    s.data_ = decrypt_payload(buf.data() + offset, buf.size() - offset, payload_nonce,
                              keys.data_key.get());
    s.key_ = std::move(keys.data_key);
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
    persist(next, key_.get(), env_);
    data_ = std::move(next);
}

bool Store::remove(const std::string& key) {
    if (!data_.contains(key)) return false;
    nlohmann::json next = data_;
    next.erase(key);
    persist(next, key_.get(), env_);
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

void Store::commit_new_key(GuardedKey new_data_key, const Envelope& next) {
    persist(data_, new_data_key.get(), next);
    key_ = std::move(new_data_key);
    env_ = next;
}

void Store::rotate(const std::string& passphrase, std::uint64_t now) {
    Unwrapped keys = unwrap(passphrase, "wrong passphrase");  // proves the passphrase
    keys.data_key.reset();  // we already hold it in key_

    // Same wrapping key (salt/params unchanged); fresh data key and wrap nonce.
    Envelope next = env_;
    next.key_created_at = now;
    GuardedKey new_data_key = alloc_guarded();
    mint_data_key(new_data_key.get(), keys.wrap_key.get(), next);
    keys.wrap_key.reset();
    commit_new_key(std::move(new_data_key), next);
}

void Store::change_passphrase(const std::string& old_pass, const std::string& new_pass,
                              std::uint64_t now) {
    if (new_pass.empty()) {
        throw std::runtime_error("empty passphrase");
    }
    unwrap(old_pass, "wrong passphrase");  // proves old_pass; both keys freed here

    // A fresh data key, not a re-wrap of the old one: an old copy of the file
    // plus the old passphrase must not unwrap the key protecting later writes.
    // At least the current default KDF params, so passwd upgrades a store made
    // with weaker ones and never downgrades a stronger one.
    Envelope next;
    GuardedKey new_data_key = mint_fresh_envelope(
        new_pass, std::max<std::uint64_t>(env_.opslimit, kDefaultOpslimit),
        std::max<std::uint64_t>(env_.memlimit, kDefaultMemlimit), now, next);
    commit_new_key(std::move(new_data_key), next);
}

}  // namespace secretov
