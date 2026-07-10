#include "store.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
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
    }
    {
        Store s = Store::open(path, kPass, kNow1);
        assert(s.get("db").value() == "postgres://x");
        assert(!s.get("api").has_value());
        assert(s.key_created_at() == kNow1);
    }
}

// 3. wrong passphrase throws.
void test_wrong_passphrase() {
    std::string path = store_path("s3");
    Store::create(path, kPass, kNow1);
    assert(throws_with([&] { Store::open(path, "nope", kNow1); },
                       "wrong passphrase or corrupted store"));
}

// 4. corrupt one ciphertext byte -> open throws.
void test_corrupt_ciphertext() {
    std::string path = store_path("s4");
    Store::create(path, kPass, kNow1);
    std::vector<unsigned char> raw = read_raw(path);
    raw.back() ^= 0x01;  // flip a byte inside the ciphertext
    write_raw(path, raw);
    assert(throws_with([&] { Store::open(path, kPass, kNow1); },
                       "wrong passphrase or corrupted store"));
}

// 5. garbage file -> "not a secretov store"-class error.
void test_garbage_file() {
    std::string path = store_path("s5");
    write_raw(path, {'n', 'o', 'p', 'e', 0, 1, 2, 3});
    assert(throws_with([&] { Store::open(path, kPass, kNow1); }, "not a secretov store"));
}

// 6. bump version byte to 2 -> "unsupported version"-class error.
void test_bad_version() {
    std::string path = store_path("s6");
    Store::create(path, kPass, kNow1);
    std::vector<unsigned char> raw = read_raw(path);
    raw[4] = 2;  // format version byte
    write_raw(path, raw);
    assert(throws_with([&] { Store::open(path, kPass, kNow1); }, "unsupported version"));
}

// 7. rotate: key_created_at updated; salt+nonce changed on disk; data survives.
void test_rotate() {
    std::string path = store_path("s7");
    std::vector<unsigned char> before;
    {
        Store s = Store::create(path, kPass, kNow1);
        s.set("secret", "value");
        before = read_raw(path);
        assert(s.key_created_at() == kNow1);

        s.rotate(kNow2);
        assert(s.key_created_at() == kNow2);
        assert(s.get("secret").value() == "value");
    }
    std::vector<unsigned char> after = read_raw(path);

    // Salt occupies bytes [5, 5+SALTBYTES); nonce sits after the three u64 fields.
    const std::size_t salt_off = 5;
    const std::size_t nonce_off = salt_off + crypto_pwhash_SALTBYTES + 8 + 8 + 8;
    bool salt_changed = std::memcmp(before.data() + salt_off, after.data() + salt_off,
                                    crypto_pwhash_SALTBYTES) != 0;
    bool nonce_changed = std::memcmp(before.data() + nonce_off, after.data() + nonce_off,
                                     crypto_secretbox_NONCEBYTES) != 0;
    assert(salt_changed);
    assert(nonce_changed);

    Store s = Store::open(path, kPass, kNow2);
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
    assert(throws_with([&] { Store::open(path, kPass, kNow1); },
                       "implausible KDF parameters"));
}

// 8. create on existing path throws.
void test_create_existing() {
    std::string path = store_path("s8");
    Store::create(path, kPass, kNow1);
    assert(throws_with([&] { Store::create(path, kPass, kNow1); }, "already exists"));
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
    test_create_existing();
    test_implausible_kdf_params();

    std::printf("OK\n");
    return 0;
}
