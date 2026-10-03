#include "paths.hpp"

// Tests must assert even in Release builds (FTXUI's CMake defaults to Release).
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

    std::filesystem::remove_all(dir);
    std::printf("OK\n");
    return 0;
}
