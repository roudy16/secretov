#include "store.hpp"

// Tests must assert even in Release builds (CMakeLists.txt defaults an unset build type to Release).
#undef NDEBUG
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

using secretov::Store;

namespace {

std::string g_dir;
const std::string kPass = "correct horse battery staple";
constexpr std::uint64_t kNow1 = 1000000000;
constexpr std::uint64_t kNow2 = 2000000000;

// Header layout: magic(4) version(1) salt opslimit(8) memlimit(8)
// key_created_at(8) wrap_nonce wrapped_key payload_nonce ...
constexpr std::size_t kSaltOff = 5;
constexpr std::size_t kOpslimitOff = kSaltOff + crypto_pwhash_SALTBYTES;
constexpr std::size_t kMemlimitOff = kOpslimitOff + 8;
constexpr std::size_t kWrapNonceOff = kMemlimitOff + 8 + 8;
constexpr std::size_t kWrappedKeyOff = kWrapNonceOff + crypto_secretbox_NONCEBYTES;
constexpr std::size_t kWrappedKeyLen = crypto_secretbox_KEYBYTES + crypto_secretbox_MACBYTES;
constexpr std::size_t kPayloadNonceOff = kWrappedKeyOff + kWrappedKeyLen;

std::uint64_t read_u64_le(const std::vector<unsigned char>& raw, std::size_t off) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i) value |= static_cast<std::uint64_t>(raw[off + i]) << (8 * i);
    return value;
}

std::string store_path(const char* name) { return g_dir + "/" + name; }

std::vector<unsigned char> read_raw(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(f)),
                                      std::istreambuf_iterator<char>());
}

void write_raw(const std::string& path, const std::vector<unsigned char>& bytes) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
}

bool same_bytes(const std::vector<unsigned char>& before, const std::vector<unsigned char>& after,
                std::size_t offset, std::size_t length) {
    return std::memcmp(before.data() + offset, after.data() + offset, length) == 0;
}

template <typename F>
bool throws_with(F&& fn, const char* needle) {
    try {
        fn();
    } catch (const std::runtime_error& e) {
        if (std::strstr(e.what(), needle) != nullptr) return true;
        std::fprintf(stderr, "unexpected message: %s\n", e.what());
    }
    return false;
}

// 1. create -> set/get/list/remove round-trip in one instance.
// 2. reopen with correct passphrase; data survives.
void test_roundtrip_and_persistence() {
    std::string path = store_path("s1");
    {
        Store s = Store::create(path, kPass, kNow1);
        assert(!s.get("missing").has_value());
        s.set("db", "postgres://x");
        s.set("api", "sk-123");
        assert(s.get("db").value() == "postgres://x");

        std::vector<std::string> keys = s.list();
        assert(keys.size() == 2 && keys[0] == "api" && keys[1] == "db");

        assert(s.remove("api"));
        assert(!s.remove("api"));
        assert(!s.get("api").has_value());
        assert(s.list().size() == 1);

        s.set("dev/p/A", "1");
        s.set("dev/p/B", "2");
        s.set("dev/p2/A", "3");
        std::map<std::string, std::string> scoped = s.get_prefix("dev/p/");
        assert(scoped.size() == 2 && scoped.at("dev/p/A") == "1" && scoped.at("dev/p/B") == "2");
        assert(s.get_prefix("nope/").empty());
    }
    {
        Store s = Store::open(path, kPass);
        assert(s.get("db").value() == "postgres://x");
        assert(!s.get("api").has_value());
        assert(s.key_created_at() == kNow1);
        assert(s.get_prefix("dev/p/").size() == 2);
    }
}

// 3. wrong passphrase throws.
void test_wrong_passphrase() {
    std::string path = store_path("s3");
    Store::create(path, kPass, kNow1);
    assert(throws_with([&] { Store::open(path, "nope"); },
                       "wrong passphrase or corrupted store"));
}

// 4. corrupt one ciphertext byte -> open throws.
void test_corrupt_ciphertext() {
    std::string path = store_path("s4");
    Store::create(path, kPass, kNow1);
    std::vector<unsigned char> raw = read_raw(path);
    raw.back() ^= 0x01;  // flip a byte inside the ciphertext
    write_raw(path, raw);
    assert(throws_with([&] { Store::open(path, kPass); },
                       "wrong passphrase or corrupted store"));
}

// 5. garbage file -> "not a secretov store"-class error.
void test_garbage_file() {
    std::string path = store_path("s5");
    write_raw(path, {'n', 'o', 'p', 'e', 0, 1, 2, 3});
    assert(throws_with([&] { Store::open(path, kPass); }, "not a secretov store"));
}

// 6. bump version byte to 3 -> "unsupported version"-class error (2 is valid).
void test_bad_version() {
    std::string path = store_path("s6");
    Store::create(path, kPass, kNow1);
    std::vector<unsigned char> raw = read_raw(path);
    raw[4] = 3;  // format version byte
    write_raw(path, raw);
    assert(throws_with([&] { Store::open(path, kPass); }, "unsupported version"));
}

// 7. rotate: key_created_at updated; salt UNCHANGED, wrap nonce + wrapped
// blob + payload nonce all change; data survives. Wrong passphrase leaves
// the store untouched.
void test_rotate() {
    std::string path = store_path("s7");
    std::vector<unsigned char> before;
    {
        Store s = Store::create(path, kPass, kNow1);
        s.set("secret", "value");
        before = read_raw(path);
        assert(s.key_created_at() == kNow1);

        assert(throws_with([&] { s.rotate("wrong", kNow2); }, "wrong passphrase"));
        assert(s.get("secret").value() == "value");
        assert(s.key_created_at() == kNow1);

        s.rotate(kPass, kNow2);
        assert(s.key_created_at() == kNow2);
        assert(s.get("secret").value() == "value");
    }
    std::vector<unsigned char> after = read_raw(path);

    assert(same_bytes(before, after, kSaltOff, crypto_pwhash_SALTBYTES));
    assert(!same_bytes(before, after, kWrapNonceOff, crypto_secretbox_NONCEBYTES));
    assert(!same_bytes(before, after, kWrappedKeyOff, kWrappedKeyLen));
    assert(!same_bytes(before, after, kPayloadNonceOff, crypto_secretbox_NONCEBYTES));

    Store s = Store::open(path, kPass);
    assert(s.get("secret").value() == "value");
    assert(s.key_created_at() == kNow2);
}

// 9. tampered memlimit -> open rejects before deriving (guards a huge alloc).
void test_implausible_kdf_params() {
    std::string path = store_path("s9");
    Store::create(path, kPass, kNow1);
    std::vector<unsigned char> raw = read_raw(path);
    // Header layout: magic(4) version(1) salt opslimit(8) memlimit(8) ...
    for (std::size_t i = 0; i < 8; ++i) raw[kMemlimitOff + i] = 0xFF;
    write_raw(path, raw);
    assert(throws_with([&] { Store::open(path, kPass); },
                       "implausible KDF parameters"));
}

// 10. change_passphrase: reopen works only with the new passphrase; data
// survives; key_created_at becomes the passwd time; wrong old passphrase /
// empty new passphrase both throw and leave the store untouched. The data key
// is fresh too: the pre-passwd header (old salt + old wrapped key) spliced
// onto the post-passwd payload must not open with the old passphrase.
void test_change_passphrase() {
    std::string path = store_path("s10");
    std::vector<unsigned char> before;
    {
        Store s = Store::create(path, kPass, kNow1);
        s.set("secret", "value");
        before = read_raw(path);

        assert(throws_with([&] { s.change_passphrase("wrong", "new pass", kNow2); },
                           "wrong passphrase"));
        assert(throws_with([&] { s.change_passphrase(kPass, "", kNow2); }, "empty passphrase"));
        assert(s.get("secret").value() == "value");
        assert(s.key_created_at() == kNow1);

        s.change_passphrase(kPass, "new pass", kNow2);
        assert(s.key_created_at() == kNow2);
        assert(s.get("secret").value() == "value");
        s.set("post", "change");  // persists under the new wrapping key
    }
    assert(throws_with([&] { Store::open(path, kPass); },
                       "wrong passphrase or corrupted store"));
    {
        Store s = Store::open(path, "new pass");
        assert(s.get("secret").value() == "value");
        assert(s.get("post").value() == "change");
        assert(s.key_created_at() == kNow2);
    }

    std::vector<unsigned char> after = read_raw(path);
    std::vector<unsigned char> spliced(before.begin(), before.begin() + kPayloadNonceOff);
    spliced.insert(spliced.end(), after.begin() + kPayloadNonceOff, after.end());
    std::string spliced_path = store_path("s10-spliced");
    write_raw(spliced_path, spliced);
    assert(throws_with([&] { Store::open(spliced_path, kPass); },
                       "wrong passphrase or corrupted store"));
}

// Hand-builds a v2 store with an empty payload under the given KDF params,
// which Store::create cannot produce (it always uses the defaults).
void write_v2_store(const std::string& path, const std::string& passphrase,
                    std::uint64_t opslimit, std::uint64_t memlimit) {
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char wrap_key[crypto_secretbox_KEYBYTES];
    unsigned char data_key[crypto_secretbox_KEYBYTES];
    unsigned char wrap_nonce[crypto_secretbox_NONCEBYTES];
    unsigned char wrapped_key[kWrappedKeyLen];
    unsigned char payload_nonce[crypto_secretbox_NONCEBYTES];
    const std::string payload = "{}";
    unsigned char ciphertext[2 + crypto_secretbox_MACBYTES];
    randombytes_buf(salt, sizeof(salt));
    randombytes_buf(data_key, sizeof(data_key));
    randombytes_buf(wrap_nonce, sizeof(wrap_nonce));
    randombytes_buf(payload_nonce, sizeof(payload_nonce));
    assert(crypto_pwhash(wrap_key, sizeof(wrap_key), passphrase.data(), passphrase.size(), salt,
                         opslimit, memlimit, crypto_pwhash_ALG_ARGON2ID13) == 0);
    crypto_secretbox_easy(wrapped_key, data_key, sizeof(data_key), wrap_nonce, wrap_key);
    crypto_secretbox_easy(ciphertext, reinterpret_cast<const unsigned char*>(payload.data()),
                          payload.size(), payload_nonce, data_key);

    std::vector<unsigned char> raw = {'S', 'C', 'T', 'V', 2};
    raw.insert(raw.end(), salt, salt + sizeof(salt));
    for (std::uint64_t field : {opslimit, memlimit, kNow1}) {
        for (int i = 0; i < 8; ++i) raw.push_back(static_cast<unsigned char>(field >> (8 * i)));
    }
    raw.insert(raw.end(), wrap_nonce, wrap_nonce + sizeof(wrap_nonce));
    raw.insert(raw.end(), wrapped_key, wrapped_key + sizeof(wrapped_key));
    raw.insert(raw.end(), payload_nonce, payload_nonce + sizeof(payload_nonce));
    raw.insert(raw.end(), ciphertext, ciphertext + sizeof(ciphertext));
    write_raw(path, raw);
}

// 12. passwd re-wraps under the current default KDF params, upgrading a store
// made with weaker ones; rotate keeps the store's params.
void test_passwd_upgrades_kdf_params() {
    std::string path = store_path("s12");
    write_v2_store(path, kPass, crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN);
    {
        Store s = Store::open(path, kPass);
        s.set("secret", "value");
        s.rotate(kPass, kNow2);
    }
    std::vector<unsigned char> rotated = read_raw(path);
    assert(read_u64_le(rotated, kOpslimitOff) == crypto_pwhash_OPSLIMIT_MIN);
    assert(read_u64_le(rotated, kMemlimitOff) == crypto_pwhash_MEMLIMIT_MIN);
    {
        Store s = Store::open(path, kPass);
        s.change_passphrase(kPass, "new pass", kNow2);
    }
    std::vector<unsigned char> upgraded = read_raw(path);
    assert(read_u64_le(upgraded, kOpslimitOff) == crypto_pwhash_OPSLIMIT_MODERATE);
    assert(read_u64_le(upgraded, kMemlimitOff) == crypto_pwhash_MEMLIMIT_MODERATE);
    Store s = Store::open(path, "new pass");
    assert(s.get("secret").value() == "value");

    std::string strong_path = store_path("s12b");
    const std::uint64_t strong_ops = crypto_pwhash_OPSLIMIT_MODERATE + 1;
    write_v2_store(strong_path, kPass, strong_ops, crypto_pwhash_MEMLIMIT_MODERATE);
    Store::open(strong_path, kPass).change_passphrase(kPass, "new pass", kNow2);
    assert(read_u64_le(read_raw(strong_path), kOpslimitOff) == strong_ops);
}

// 13. rotate and passwd whose write fails (read-only dir) leave memory
// unchanged: the store keeps working, and a later set persists under the OLD
// passphrase and key_created_at.
void test_failed_rotate_and_passwd_leave_store_unchanged() {
    std::string dir = store_path("s13");
    std::filesystem::create_directory(dir);
    std::string path = dir + "/store";
    {
        Store s = Store::create(path, kPass, kNow1);
        s.set("secret", "value");
        std::filesystem::permissions(dir, std::filesystem::perms::owner_read |
                                              std::filesystem::perms::owner_exec);
        assert(throws_with([&] { s.change_passphrase(kPass, "new pass", kNow2); }, "create"));
        assert(throws_with([&] { s.rotate(kPass, kNow2); }, "create"));
        std::filesystem::permissions(dir, std::filesystem::perms::owner_all);
        assert(s.key_created_at() == kNow1);
        assert(s.get("secret").value() == "value");
        s.set("after", "failed writes");
    }
    assert(throws_with([&] { Store::open(path, "new pass"); },
                       "wrong passphrase or corrupted store"));
    Store s = Store::open(path, kPass);
    assert(s.get("secret").value() == "value");
    assert(s.get("after").value() == "failed writes");
    assert(s.key_created_at() == kNow1);
}

// 8. create on existing path throws.
void test_create_existing() {
    std::string path = store_path("s8");
    Store::create(path, kPass, kNow1);
    assert(throws_with([&] { Store::create(path, kPass, kNow1); }, "already exists"));
}

// 11. version-1 fixture migrates in place on open: data readable, file grows
// and its version byte becomes 2, and a second open still works. Wrong
// passphrase against the v1 fixture still throws.
const unsigned char kV1Fixture[] = {
    0x53, 0x43, 0x54, 0x56, 0x01, 0x34, 0xf6, 0xca, 0xb5, 0xd8, 0xf0, 0x95,
    0xa2, 0x9b, 0xa6, 0xd2, 0xd8, 0x43, 0xf0, 0x87, 0x45, 0x03, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xf1, 0x53, 0x65, 0x00, 0x00, 0x00, 0x00, 0x24, 0xc3, 0xf7,
    0x1e, 0x96, 0x05, 0xb1, 0x78, 0x76, 0xbc, 0x7e, 0x78, 0x7b, 0x5b, 0x47,
    0x7e, 0x94, 0xdd, 0x07, 0xa6, 0x5d, 0x06, 0x0b, 0x39, 0x0b, 0xc4, 0x0e,
    0xf6, 0x62, 0x62, 0x92, 0x38, 0x62, 0xff, 0x52, 0x7f, 0x69, 0xa2, 0x92,
    0x2c, 0x5e, 0x62, 0x61, 0x92, 0xed, 0xc1, 0x89, 0x9e, 0x00, 0x18, 0xd0,
    0xc7, 0x0b, 0x0d, 0x9a, 0xa6, 0xa5, 0xf1, 0x07, 0xfa, 0x31, 0x45, 0x52,
    0x36, 0x5d, 0x0b, 0x5a, 0xd0, 0xbd, 0xc9, 0x3a, 0x79, 0x9b, 0x1e, 0xf8,
    0x91,
};
constexpr std::size_t kV1FixtureLen = sizeof(kV1Fixture);

void test_v1_migration() {
    std::string path = store_path("s11");
    write_raw(path, std::vector<unsigned char>(kV1Fixture, kV1Fixture + kV1FixtureLen));

    {
        Store s = Store::open(path, kPass);
        assert(s.get("db").value() == "postgres://x");
        assert(s.get("api").value() == "sk-123");
    }

    std::vector<unsigned char> migrated = read_raw(path);
    assert(migrated.size() > kV1FixtureLen);
    assert(migrated[4] == 2);  // format version byte

    Store s2 = Store::open(path, kPass);
    assert(s2.get("db").value() == "postgres://x");
    assert(s2.get("api").value() == "sk-123");

    std::string wrong_path = store_path("s11b");
    write_raw(wrong_path, std::vector<unsigned char>(kV1Fixture, kV1Fixture + kV1FixtureLen));
    assert(throws_with([&] { Store::open(wrong_path, "wrong"); },
                       "wrong passphrase or corrupted store"));
}

}  // namespace

int main() {
    char tmpl[] = "/tmp/secretov_test_XXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir) {
        std::perror("mkdtemp");
        return 1;
    }
    g_dir = dir;

    test_roundtrip_and_persistence();
    test_wrong_passphrase();
    test_corrupt_ciphertext();
    test_garbage_file();
    test_bad_version();
    test_rotate();
    test_change_passphrase();
    test_create_existing();
    test_implausible_kdf_params();
    test_v1_migration();
    test_passwd_upgrades_kdf_params();
    test_failed_rotate_and_passwd_leave_store_unchanged();

    std::filesystem::remove_all(g_dir);
    std::printf("OK\n");
    return 0;
}
