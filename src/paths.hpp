#pragma once

// Path resolution and small shared client/daemon helpers (Milestone 3).
// Header-only: these are thin wrappers over env/filesystem/termios and are
// used by main, the daemon, and the client.

#include <fcntl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace secretov {

struct Paths {
    std::string store;
    std::string token;
    std::string socket;
};

inline std::string env_or(const char* name, const std::string& fallback) {
    const char* v = std::getenv(name);
    return (v && *v) ? std::string(v) : fallback;
}

inline std::string home_dir() {
    const char* home = std::getenv("HOME");
    if (!home || !*home) {
        throw std::runtime_error("HOME is not set; cannot resolve default paths");
    }
    return home;
}

inline Paths resolve_paths() {
    Paths p;
    p.store = env_or("XDG_DATA_HOME", home_dir() + "/.local/share") + "/secretov/store";
    p.token = env_or("XDG_CONFIG_HOME", home_dir() + "/.config") + "/secretov/token";
    const char* runtime = std::getenv("XDG_RUNTIME_DIR");
    if (runtime && *runtime) {
        p.socket = std::string(runtime) + "/secretov.sock";
    } else {
        // No XDG_RUNTIME_DIR: put the socket in a private 0700 dir under /tmp so
        // a placing-a-socket-in-shared-/tmp race can't hand it to another UID.
        std::string dir = "/tmp/secretov-" + std::to_string(::getuid());
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
        p.socket = dir + "/secretov.sock";
    }
    return p;
}

// Recursively create `dir` and any missing parents with mode 0700.
inline void mkdir_p(const std::string& dir) {
    if (dir.empty() || dir == "/") return;
    std::string partial;
    std::size_t i = 0;
    if (dir[0] == '/') {
        partial = "/";
        i = 1;
    }
    while (i <= dir.size()) {
        if (i == dir.size() || dir[i] == '/') {
            if (!partial.empty() && partial != "/") {
                if (::mkdir(partial.c_str(), 0700) != 0 && errno != EEXIST) {
                    throw std::runtime_error("mkdir '" + partial + "': " + std::strerror(errno));
                }
            }
            if (i < dir.size()) partial.push_back('/');
        } else {
            partial.push_back(dir[i]);
        }
        ++i;
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

// Atomic write via tmp + fsync + rename, mirroring Store::persist.
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
}

// Read a passphrase. On a tty: prompt on stderr, disable echo (restored after).
// Otherwise: read one line from stdin (enables scripted testing). Empty errors.
inline std::string read_passphrase(const std::string& prompt) {
    std::string line;
    if (::isatty(STDIN_FILENO)) {
        std::cerr << prompt << std::flush;
        termios old_termios{};
        bool have_termios = ::tcgetattr(STDIN_FILENO, &old_termios) == 0;
        if (have_termios) {
            termios no_echo = old_termios;
            no_echo.c_lflag &= ~static_cast<tcflag_t>(ECHO);
            ::tcsetattr(STDIN_FILENO, TCSANOW, &no_echo);
        }
        std::getline(std::cin, line);
        if (have_termios) {
            ::tcsetattr(STDIN_FILENO, TCSANOW, &old_termios);
        }
        std::cerr << "\n";
    } else {
        std::getline(std::cin, line);
    }
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) {
        throw std::runtime_error("empty passphrase");
    }
    return line;
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
