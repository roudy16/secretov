#pragma once

// Encrypted secrets store (Milestone 2).
//
// On-disk file format (plaintext header, then ciphertext):
//   offset  size                          field
//   0       4                             magic = "SCTV"
//   4       1                             format version = 1
//   5       crypto_pwhash_SALTBYTES       Argon2id salt
//   +8      8                             opslimit  (uint64 little-endian)
//   +8      8                             memlimit  (uint64 little-endian)
//   +8      8                             key_created_at, unix seconds (uint64 LE)
//   +N      crypto_secretbox_NONCEBYTES   nonce
//   rest    variable                      crypto_secretbox ciphertext
//
// Ciphertext is XSalsa20-Poly1305 (crypto_secretbox) over a UTF-8 nlohmann::json
// object mapping secret name -> value (flat string->string map). All multi-byte
// integers are explicitly little-endian (manual byte packing).

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <sodium.h>

namespace secretov {

class Store {
   public:
    static Store create(const std::string& path, const std::string& passphrase,
                        std::uint64_t now);
    static Store open(const std::string& path, const std::string& passphrase,
                      std::uint64_t now);

    Store(const Store&) = delete;
    Store& operator=(const Store&) = delete;
    Store(Store&& other) noexcept;
    Store& operator=(Store&& other) noexcept;
    ~Store();

    std::optional<std::string> get(const std::string& key) const;
    void set(const std::string& key, const std::string& value);
    bool remove(const std::string& key);
    std::vector<std::string> list() const;
    // Every key starting with `prefix` (plain string prefix; callers pass
    // "env/project/" so matching is segment-safe).
    std::map<std::string, std::string> get_prefix(const std::string& prefix) const;

    void rotate(std::uint64_t now);
    // Re-key the store under a different passphrase (fresh salt, re-encrypt,
    // retained passphrase replaced). Caller verifies the old passphrase first.
    void change_passphrase(const std::string& new_passphrase, std::uint64_t now);
    // Constant-time comparison against the retained passphrase.
    bool passphrase_matches(const std::string& given) const;
    std::uint64_t key_created_at() const { return key_created_at_; }

   private:
    Store() = default;

    void derive_key(const std::string& passphrase);
    void rekey(const unsigned char* pass, std::size_t pass_len, std::uint64_t now);
    void persist() const;
    void wipe();

    std::string path_;
    nlohmann::json data_ = nlohmann::json::object();

    // Guarded (sodium_mlock) secret material.
    unsigned char* passphrase_ = nullptr;
    std::size_t passphrase_len_ = 0;
    unsigned char* key_ = nullptr;  // crypto_secretbox_KEYBYTES

    unsigned char salt_[crypto_pwhash_SALTBYTES] = {};
    std::uint64_t opslimit_ = 0;
    std::uint64_t memlimit_ = 0;
    std::uint64_t key_created_at_ = 0;
};

}  // namespace secretov
