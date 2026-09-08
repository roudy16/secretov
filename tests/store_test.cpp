#include "store.hpp"

// Tests must assert even in Release builds (FTXUI's CMake defaults to Release).
#undef NDEBUG
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
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

template <typename F>
bool throws_with(F&& fn, const char* needle) {
    try {
        fn();
    } catch (const std::runtime_error& e) {
        return std::strstr(e.what(), needle) != nullptr;
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

    // Header layout: magic(4) version(1) salt opslimit(8) memlimit(8)
    // key_created_at(8) wrap_nonce wrapped_key payload_nonce ...
    const std::size_t salt_off = 5;
    const std::size_t wrap_nonce_off = salt_off + crypto_pwhash_SALTBYTES + 8 + 8 + 8;
    const std::size_t wrapped_key_off = wrap_nonce_off + crypto_secretbox_NONCEBYTES;
    const std::size_t wrapped_key_len = crypto_secretbox_KEYBYTES + crypto_secretbox_MACBYTES;
    const std::size_t payload_nonce_off = wrapped_key_off + wrapped_key_len;

    bool salt_unchanged = std::memcmp(before.data() + salt_off, after.data() + salt_off,
                                      crypto_pwhash_SALTBYTES) == 0;
    bool wrap_nonce_changed = std::memcmp(before.data() + wrap_nonce_off,
                                          after.data() + wrap_nonce_off,
                                          crypto_secretbox_NONCEBYTES) != 0;
    bool wrapped_key_changed = std::memcmp(before.data() + wrapped_key_off,
                                           after.data() + wrapped_key_off,
                                           wrapped_key_len) != 0;
    bool payload_nonce_changed = std::memcmp(before.data() + payload_nonce_off,
                                             after.data() + payload_nonce_off,
                                             crypto_secretbox_NONCEBYTES) != 0;
    assert(salt_unchanged);
    assert(wrap_nonce_changed);
    assert(wrapped_key_changed);
    assert(payload_nonce_changed);

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
    const std::size_t memlimit_off = 5 + crypto_pwhash_SALTBYTES + 8;
    for (std::size_t i = 0; i < 8; ++i) raw[memlimit_off + i] = 0xFF;
    write_raw(path, raw);
    assert(throws_with([&] { Store::open(path, kPass); },
                       "implausible KDF parameters"));
}

// 10. change_passphrase: reopen works only with the new passphrase; data
// survives; key_created_at unchanged; wrong old passphrase / empty new
// passphrase both throw and leave the store untouched.
void test_change_passphrase() {
    std::string path = store_path("s10");
    {
        Store s = Store::create(path, kPass, kNow1);
        s.set("secret", "value");

        assert(throws_with([&] { s.change_passphrase("wrong", "new pass"); }, "wrong passphrase"));
        assert(throws_with([&] { s.change_passphrase(kPass, ""); }, "empty passphrase"));
        assert(s.get("secret").value() == "value");

        s.change_passphrase(kPass, "new pass");
        assert(s.key_created_at() == kNow1);
        assert(s.get("secret").value() == "value");
        s.set("post", "change");  // persists under the new wrapping key
    }
    assert(throws_with([&] { Store::open(path, kPass); },
                       "wrong passphrase or corrupted store"));
    Store s = Store::open(path, "new pass");
    assert(s.get("secret").value() == "value");
    assert(s.get("post").value() == "change");
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

    std::printf("OK\n");
    return 0;
}
