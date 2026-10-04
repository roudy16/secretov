#include "paths.hpp"
#include "protocol.hpp"

// Tests must assert even in Release builds (CMakeLists.txt defaults an unset build type to Release).
#undef NDEBUG
#include <unistd.h>

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace {

// Point stdin at a pipe pre-filled with `input`.
void stdin_from(const std::string& input) {
    int fds[2];
    assert(::pipe(fds) == 0);
    assert(::write(fds[1], input.data(), input.size()) == static_cast<ssize_t>(input.size()));
    ::close(fds[1]);
    assert(::dup2(fds[0], STDIN_FILENO) == STDIN_FILENO);
    ::close(fds[0]);
}

void test_secret_lines_from_one_pipe() {
    // passwd reads two passphrases from one pipe: nothing past a newline may be consumed.
    stdin_from("first\r\nsecond\n");
    assert(secretov::read_passphrase("") == "first");
    assert(secretov::read_passphrase("") == "second");
    bool threw = false;
    try {
        secretov::read_passphrase("");
    } catch (const std::runtime_error&) {
        threw = true;
    }
    assert(threw);  // EOF -> empty passphrase
}

void test_secret_line_cap() {
    stdin_from(std::string(5000, 'a') + "\n");
    bool threw = false;
    try {
        secretov::read_secret_line("");
    } catch (const std::runtime_error& e) {
        threw = std::string(e.what()).find("longer than") != std::string::npos;
    }
    assert(threw);
}

void test_write_file_atomic_relative_path(const std::string& dir) {
    // A bare file name has no parent component; the dir fsync must use ".".
    assert(::chdir(dir.c_str()) == 0);
    secretov::write_file_atomic("relative_file", "contents", 0600);
    assert(secretov::read_file_string(dir + "/relative_file") == "contents");
    secretov::write_file_atomic(dir + "/nested/abs_file", "more", 0600);
    assert(secretov::read_file_string(dir + "/nested/abs_file") == "more");
}

void test_write_file_atomic_dir_fsync_failure_is_committed(const std::string& dir) {
    // A dir without read permission allows the rename but not the dir open for
    // fsync: the write has happened, so it must not throw.
    std::string no_read_dir = dir + "/no_read";
    assert(::mkdir(no_read_dir.c_str(), 0300) == 0);
    secretov::write_file_atomic(no_read_dir + "/f", "committed", 0600);
    assert(::chmod(no_read_dir.c_str(), 0700) == 0);
    assert(secretov::read_file_string(no_read_dir + "/f") == "committed");
}

void test_resolve_paths_without_home(const std::string& dir) {
    // Both XDG dirs set: HOME is never consulted, so its absence must not throw.
    assert(::setenv("XDG_DATA_HOME", (dir + "/data").c_str(), 1) == 0);
    assert(::setenv("XDG_CONFIG_HOME", (dir + "/config").c_str(), 1) == 0);
    assert(::setenv("XDG_RUNTIME_DIR", dir.c_str(), 1) == 0);
    assert(::unsetenv("HOME") == 0);
    secretov::Paths resolved = secretov::resolve_paths();
    assert(resolved.store == dir + "/data/secretov/" + secretov::kStoreFileName);
    assert(resolved.registry == dir + "/config/secretov/" + secretov::kRegistryFileName);
    assert(::unsetenv("XDG_CONFIG_HOME") == 0);
    bool threw = false;
    try {
        secretov::resolve_paths();
    } catch (const std::runtime_error& e) {
        threw = std::string(e.what()).find("HOME is not set") != std::string::npos;
    }
    assert(threw);
}

void test_parse_request() {
    using secretov::parse_request;
    assert(!parse_request(""));
    assert(!parse_request("not json"));
    assert(!parse_request("[]"));
    assert(!parse_request("\"str\""));
    assert(!parse_request(R"({"op":"get"})"));
    assert(!parse_request(R"({"token":"t"})"));
    assert(!parse_request(R"({"token":1,"op":"get"})"));
    assert(!parse_request(R"({"token":"t","op":null})"));
    assert(!parse_request(R"({"token":"t","op":"get","key":5})"));
    assert(!parse_request(R"({"token":"t","op":"rotate","old":["x"]})"));
    assert(!parse_request(R"({"token":"t","op":"passwd","new":{}})"));

    auto minimal = parse_request(R"({"token":"t","op":"list"})");
    assert(minimal && minimal->token == "t" && minimal->op == "list");
    assert(minimal->key.empty() && minimal->value.empty());
    assert(minimal->old_pass.empty() && minimal->new_pass.empty());

    auto full = parse_request(
        R"({"token":"t","op":"passwd","key":"k","value":"v","old":"o","new":"n","extra":1})");
    assert(full && full->key == "k" && full->value == "v");
    assert(full->old_pass == "o" && full->new_pass == "n");
}

}  // namespace

int main() {
    char tmpl[] = "/tmp/secretov_paths_test_XXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir) {
        std::perror("mkdtemp");
        return 1;
    }

    test_secret_lines_from_one_pipe();
    test_secret_line_cap();
    test_write_file_atomic_relative_path(dir);
    test_write_file_atomic_dir_fsync_failure_is_committed(dir);
    test_resolve_paths_without_home(dir);
    test_parse_request();

    std::filesystem::remove_all(dir);
    std::printf("OK\n");
    return 0;
}
