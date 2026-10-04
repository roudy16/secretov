#pragma once

// Path resolution and small shared client/daemon helpers (Milestone 3).
// Header-only: these are thin wrappers over env/filesystem/termios and are
// used by main, the daemon, and the client.

#include <fcntl.h>
#include <sodium.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace secretov {

// Single source of truth for on-disk names.
inline constexpr const char* kAppName = "secretov";
inline constexpr const char* kStoreFileName = "store";
inline constexpr const char* kTokenFileName = "token";
inline constexpr const char* kRegistryFileName = "projects.yaml";
inline constexpr const char* kSocketFileName = "secretov.sock";
inline constexpr const char* kManifestFileName = ".secretov.yaml";
inline constexpr const char* kEnvOverrideVar = "SECRETOV_ENV";

struct Paths {
    std::string store;
    std::string token;
    std::string registry;
    std::string socket;
};

inline std::string home_dir() {
    const char* home = std::getenv("HOME");
    if (!home || !*home) {
        throw std::runtime_error("HOME is not set; cannot resolve default paths");
    }
    return home;
}

inline std::string xdg_dir_or_home(const char* xdg_var, const char* home_suffix) {
    const char* xdg_value = std::getenv(xdg_var);
    return (xdg_value && *xdg_value) ? std::string(xdg_value) : home_dir() + home_suffix;
}

inline Paths resolve_paths() {
    Paths p;
    const std::string app = std::string("/") + kAppName + "/";
    p.store = xdg_dir_or_home("XDG_DATA_HOME", "/.local/share") + app + kStoreFileName;
    const std::string config_dir = xdg_dir_or_home("XDG_CONFIG_HOME", "/.config") + app;
    p.token = config_dir + kTokenFileName;
    p.registry = config_dir + kRegistryFileName;
    const char* runtime = std::getenv("XDG_RUNTIME_DIR");
    if (runtime && *runtime) {
        p.socket = std::string(runtime) + "/" + kSocketFileName;
    } else {
        // No XDG_RUNTIME_DIR: put the socket in a private 0700 dir under /tmp so
        // a placing-a-socket-in-shared-/tmp race can't hand it to another UID.
        std::string dir = "/tmp/" + std::string(kAppName) + "-" + std::to_string(::getuid());
        if (::mkdir(dir.c_str(), 0700) != 0) {
            if (errno != EEXIST) {
                throw std::runtime_error("mkdir '" + dir + "': " + std::strerror(errno));
            }
            struct stat st{};
            if (::lstat(dir.c_str(), &st) != 0) {
                throw std::runtime_error("stat '" + dir + "': " + std::strerror(errno));
            }
            if (!S_ISDIR(st.st_mode) || st.st_uid != ::getuid() ||
                (st.st_mode & 07777) != 0700) {
                throw std::runtime_error("insecure socket dir '" + dir +
                                         "': must be a 0700 dir owned by our uid");
            }
        }
        p.socket = dir + "/" + kSocketFileName;
    }
    return p;
}

// Recursively create `dir` and any missing parents with mode 0700.
inline void mkdir_p(const std::string& dir) {
    if (dir.empty() || dir == "/") return;
    mode_t old_umask = ::umask(0077);
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    ::umask(old_umask);
    if (ec) {
        throw std::runtime_error("mkdir '" + dir + "': " + ec.message());
    }
}

inline void ensure_parent_dir(const std::string& path) {
    std::size_t slash = path.find_last_of('/');
    if (slash == std::string::npos || slash == 0) return;
    mkdir_p(path.substr(0, slash));
}

inline std::string read_file_string(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("open '" + path + "': " + std::strerror(errno));
    }
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// Atomic write via tmp + fsync + rename + parent-dir fsync (without the last,
// a power cut can roll the rename back after we reported success).
inline void write_file_atomic(const std::string& path, const std::string& contents, mode_t mode) {
    ensure_parent_dir(path);
    std::string tmp = path + ".tmp";
    ::unlink(tmp.c_str());
    int fd = ::open(tmp.c_str(), O_CREAT | O_EXCL | O_WRONLY, mode);
    if (fd < 0) {
        throw std::runtime_error("create '" + tmp + "': " + std::strerror(errno));
    }
    std::size_t written = 0;
    while (written < contents.size()) {
        ssize_t n = ::write(fd, contents.data() + written, contents.size() - written);
        if (n < 0) {
            int e = errno;
            ::close(fd);
            ::unlink(tmp.c_str());
            throw std::runtime_error("write '" + tmp + "': " + std::strerror(e));
        }
        written += static_cast<std::size_t>(n);
    }
    if (::fsync(fd) != 0) {
        int e = errno;
        ::close(fd);
        ::unlink(tmp.c_str());
        throw std::runtime_error("fsync '" + tmp + "': " + std::strerror(e));
    }
    if (::close(fd) != 0) {
        int e = errno;
        ::unlink(tmp.c_str());
        throw std::runtime_error("close '" + tmp + "': " + std::strerror(e));
    }
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        int e = errno;
        ::unlink(tmp.c_str());
        throw std::runtime_error("rename '" + tmp + "' -> '" + path + "': " + std::strerror(e));
    }
    // The rename has replaced `path`: callers (Store::persist and the passwd/
    // rotate commit) treat a throw as "nothing changed", so from here a failure
    // is only a warning. ponytail: durability is best-effort past the rename.
    std::string dir = std::filesystem::path(path).parent_path().string();
    if (dir.empty()) dir = ".";
    int dir_fd = ::open(dir.c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    if (dir_fd < 0 || ::fsync(dir_fd) != 0) {
        std::cerr << "secretov: warning: wrote '" << path << "' but could not fsync dir '" << dir
                  << "': " << std::strerror(errno) << " (a power loss may undo the write)\n";
    }
    if (dir_fd >= 0) ::close(dir_fd);
}

// Zeroes the whole allocation, not just size(): erase/backspace and
// shrinking leave stale bytes in the capacity tail.
inline void wipe(std::string& text) {
    text.resize(text.capacity());
    sodium_memzero(text.data(), text.size());
    text.clear();
}

// Read one secret line from stdin. On a tty: prompt on stderr with echo off
// (restored after); refuse (discarding it) any input queued past the line, and
// a line the terminal may have truncated.
// Otherwise: read one line (enables scripted use). Bytes go
// straight from ::read into a pre-reserved buffer: no stdio buffer or string
// reallocation keeps an unscrubbed copy, and nothing past the newline is
// consumed, so successive calls can read successive lines of one pipe.
inline std::string read_secret_line(const std::string& prompt) {
    // ponytail: fixed line cap so the buffer never reallocates.
    constexpr std::size_t kMaxSecretLineBytes = 4096;
    // The canonical tty line discipline (N_TTY_BUF_SIZE 4096) keeps the first
    // 4095 bytes of a line and silently drops the rest, so a line that long
    // may be truncated.
    constexpr std::size_t kMaxTtyLineBytes = 4095;
    const bool on_tty = ::isatty(STDIN_FILENO);
    termios old_termios{};
    bool echo_disabled = false;
    if (on_tty) {
        // A background job touching the terminal gets SIGTTOU/SIGTTIN and
        // stops; the user's next typed line then lands in the shell (and its
        // history) instead of here.
        pid_t foreground_pgrp = ::tcgetpgrp(STDIN_FILENO);
        if (foreground_pgrp != -1 && foreground_pgrp != ::getpgrp()) {
            throw std::runtime_error(
                "cannot prompt from a background process; run it in the foreground "
                "or pipe the input on stdin");
        }
        if (::tcgetattr(STDIN_FILENO, &old_termios) == 0) {
            termios no_echo = old_termios;
            no_echo.c_lflag &= ~static_cast<tcflag_t>(ECHO);
            echo_disabled = ::tcsetattr(STDIN_FILENO, TCSANOW, &no_echo) == 0;
        }
        std::cerr << prompt << std::flush;
    }
    std::string line;
    line.reserve(kMaxSecretLineBytes);
    bool too_long = false;
    int read_errno = 0;
    for (;;) {
        char byte;
        ssize_t n = ::read(STDIN_FILENO, &byte, 1);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) read_errno = errno;
        if (n <= 0 || byte == '\n') break;
        if (line.size() == kMaxSecretLineBytes) {
            too_long = true;
            break;
        }
        line.push_back(byte);
    }
    bool tty_input_left = false;
    if (echo_disabled) {
        // Lines after the first (a pasted PEM key) would otherwise reach the
        // shell once we exit: run as commands, saved to history. Briefly drop
        // ICANON so a trailing partial line counts too. The tty queue holds
        // only ~4 KiB and the terminal writes the rest of a longer paste as we
        // read, so drain until the line has been quiet for 100 ms, then
        // restore with TCSAFLUSH, which discards whatever is still queued.
        termios peek = old_termios;
        peek.c_lflag &= ~static_cast<tcflag_t>(ECHO | ICANON);
        peek.c_cc[VMIN] = 0;
        peek.c_cc[VTIME] = 1;  // 100 ms: a paste can arrive in chunks
        if (::tcsetattr(STDIN_FILENO, TCSANOW, &peek) == 0) {
            // ponytail: drain cap; past it the rest of an endless stream reaches the shell.
            constexpr std::size_t kMaxDrainBytes = 1 << 20;
            char drain_buffer[4096];
            std::size_t drained_bytes = 0;
            while (drained_bytes < kMaxDrainBytes) {
                ssize_t n = ::read(STDIN_FILENO, drain_buffer, sizeof(drain_buffer));
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) break;
                tty_input_left = true;
                drained_bytes += static_cast<std::size_t>(n);
            }
            sodium_memzero(drain_buffer, sizeof(drain_buffer));
        }
        ::tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_termios);
    }
    if (on_tty) std::cerr << "\n";
    const bool tty_truncated = on_tty && line.size() >= kMaxTtyLineBytes;
    if (read_errno != 0 || too_long || tty_input_left || tty_truncated) {
        wipe(line);
        if (too_long) {
            throw std::runtime_error("input line longer than " +
                                     std::to_string(kMaxSecretLineBytes) + " bytes");
        }
        if (tty_truncated) {
            throw std::runtime_error("line may have been truncated by the terminal (" +
                                     std::to_string(kMaxTtyLineBytes) +
                                     "-byte limit); pipe long values on stdin instead");
        }
        if (tty_input_left) {
            throw std::runtime_error(
                "more input followed the line on the terminal (multi-line paste?); "
                "discarded it; pipe multi-line values on stdin instead");
        }
        throw std::runtime_error(std::string("read stdin: ") + std::strerror(read_errno));
    }
    if (!line.empty() && line.back() == '\r') line.pop_back();
    return line;
}

// read_secret_line, but an empty passphrase is an error.
inline std::string read_passphrase(const std::string& prompt) {
    std::string passphrase = read_secret_line(prompt);
    if (passphrase.empty()) {
        throw std::runtime_error("empty passphrase");
    }
    return passphrase;
}

// Strip trailing whitespace/newlines (used when reading the token file).
inline std::string rstrip(const std::string& s) {
    std::size_t end = s.size();
    while (end > 0 && (s[end - 1] == '\n' || s[end - 1] == '\r' || s[end - 1] == ' ' ||
                       s[end - 1] == '\t')) {
        --end;
    }
    return s.substr(0, end);
}

}  // namespace secretov
