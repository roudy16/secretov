#pragma once

// Encrypted secrets store (envelope encryption, format version 2).
//
// On-disk file format (plaintext header, then ciphertext):
//   offset  size                                    field
//   0       4                                       magic = "SCTV"
//   4       1                                       format version = 2
//   5       crypto_pwhash_SALTBYTES                 Argon2id salt
//   +N      8                                       opslimit  (uint64 little-endian)
//   +8      8                                       memlimit  (uint64 little-endian)
//   +8      8                                       key_created_at, unix seconds (uint64 LE)
//   +8      crypto_secretbox_NONCEBYTES              wrap nonce
//   +N      crypto_secretbox_KEYBYTES+MACBYTES       wrapped data key =
//                                                     secretbox(data_key, wrap_nonce, wrapping_key)
//   +N      crypto_secretbox_NONCEBYTES              payload nonce
//   rest    variable                                 secretbox(json payload, payload_nonce, data_key)
//
// Envelope encryption: a random 256-bit data key encrypts the JSON payload
// (crypto_secretbox, XSalsa20-Poly1305). The data key is itself encrypted
// ("wrapped") by a wrapping key, Argon2id-derived from the passphrase, with
// its own nonce. The wrapping key is used only to wrap/unwrap the data key
// and is zeroed immediately after each use — the Store never retains it or
// the passphrase, only the data key (mlock'd, for the Store's lifetime).
//
// Version 1 stores (no envelope: the derived key encrypted the payload
// directly) are migrated to version 2 in place on first open. One-way.

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <sodium.h>

namespace secretov {

// Zeroes, munlocks and frees a crypto_secretbox_KEYBYTES buffer.
struct GuardedFree {
    void operator()(unsigned char* key) const noexcept;
};
// An mlock'd key buffer of crypto_secretbox_KEYBYTES, wiped on release.
using GuardedKey = std::unique_ptr<unsigned char, GuardedFree>;

class Store {
   public:
    static Store create(const std::string& path, const std::string& passphrase,
                        std::uint64_t now);
    // Migrates a version-1 store in place on first open.
    static Store open(const std::string& path, const std::string& passphrase);

    Store(const Store&) = delete;
    Store& operator=(const Store&) = delete;
    Store(Store&& other) noexcept = default;
    Store& operator=(Store&& other) = delete;

    std::optional<std::string> get(const std::string& key) const;
    void set(const std::string& key, const std::string& value);
    bool remove(const std::string& key);
    std::vector<std::string> list() const;
    // Every key starting with `prefix` (plain string prefix; callers pass
    // "env/project/" so matching is segment-safe).
    std::map<std::string, std::string> get_prefix(const std::string& prefix) const;

    // New data key. Verifies `passphrase` by unwrapping the stored data key;
    // throws "wrong passphrase" on MAC failure. Re-encrypts the payload
    // under the fresh key.
    void rotate(const std::string& passphrase, std::uint64_t now);
    // New wrapping key AND new data key: fresh salt, current default KDF
    // params, derive from new_pass, re-encrypt the payload under a fresh data
    // key wrapped by it. Verifies old_pass first (same way). key_created_at
    // becomes `now`.
    void change_passphrase(const std::string& old_pass, const std::string& new_pass,
                           std::uint64_t now);
    std::uint64_t key_created_at() const { return env_.key_created_at; }

   private:
    Store() = default;

    // Plaintext header fields written ahead of the payload.
    struct Envelope {
        unsigned char salt[crypto_pwhash_SALTBYTES] = {};
        std::uint64_t opslimit = 0;
        std::uint64_t memlimit = 0;
        std::uint64_t key_created_at = 0;
        unsigned char wrap_nonce[crypto_secretbox_NONCEBYTES] = {};
        unsigned char wrapped_key[crypto_secretbox_KEYBYTES + crypto_secretbox_MACBYTES] = {};
    };

    // Wrapping key derived from a passphrase plus the data key it unwrapped.
    struct Unwrapped {
        GuardedKey wrap_key;
        GuardedKey data_key;
    };
    // One Argon2id derivation that both proves the passphrase (the stored
    // blob must unwrap) and hands back the wrapping key for re-wrapping.
    // Throws `fail_msg` on MAC failure.
    Unwrapped unwrap(const std::string& passphrase, const char* fail_msg) const;
    // Fills `data_key` with a fresh random key and wraps it under `wrap_key`
    // into `envelope` with a fresh wrap nonce.
    static void mint_data_key(unsigned char* data_key, const unsigned char* wrap_key,
                              Envelope& envelope);
    // Fresh salt, the given KDF params and `now` into `envelope`, then a fresh
    // data key wrapped under the key derived from `passphrase`. Returns the
    // data key.
    static GuardedKey mint_fresh_envelope(const std::string& passphrase, std::uint64_t opslimit,
                                          std::uint64_t memlimit, std::uint64_t now,
                                          Envelope& envelope);
    // Fills the header fields v1 and v2 share and validates the KDF params;
    // returns the offset just past them. `buf` must already be size-checked.
    static std::size_t read_common_header(const std::vector<unsigned char>& buf,
                                          Envelope& envelope);
    void persist(const nlohmann::json& data, const unsigned char* data_key,
                 const Envelope& envelope) const;
    // Persists data_ under `new_data_key` and `next`, then adopts both. On a
    // failed write the key is freed and nothing changes.
    void commit_new_key(GuardedKey new_data_key, const Envelope& next);

    std::string path_;
    nlohmann::json data_ = nlohmann::json::object();

    // Guarded (sodium_mlock) secret material. The Store retains only the
    // data key; the passphrase and wrapping key are never retained.
    GuardedKey key_;  // the data key
    Envelope env_;
};

}  // namespace secretov
