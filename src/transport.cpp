#include "transport.hpp"

#include <sodium.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <utility>

#include "paths.hpp"

namespace secretov {

namespace {

[[noreturn]] void throw_errno(const std::string& what) {
    throw std::runtime_error(what + ": " + std::strerror(errno));
}

// ponytail: lines past this reallocate the receive buffer, leaving unscrubbed
// copies on the heap; requests carrying passphrases are far smaller.
constexpr std::size_t kInitialBufferBytes = 64 << 10;

// EINTR-safe read; -1 on real error, 0 on EOF, >0 bytes read otherwise.
ssize_t read_retry(int fd, char* buf, size_t len) {
    ssize_t n;
    do {
        n = ::read(fd, buf, len);
    } while (n < 0 && errno == EINTR);
    return n;
}

// nullopt when `path` does not fit in sun_path (with its terminator).
std::optional<sockaddr_un> unix_address(const std::string& path) {
    sockaddr_un addr{};
    if (path.size() >= sizeof(addr.sun_path)) {
        return std::nullopt;
    }
    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, path.c_str(), path.size());
    return addr;
}

}  // namespace

Connection::Connection(int fd) : fd_(fd) { buffer_.reserve(kInitialBufferBytes); }

Connection::~Connection() {
    wipe(buffer_);
    if (fd_ >= 0) {
        ::close(fd_);
    }
}

Connection::Connection(Connection&& other) noexcept
    : fd_(other.fd_), buffer_(std::move(other.buffer_)), scanned_(other.scanned_), timed_out_(other.timed_out_) {
    other.fd_ = -1;
}

std::optional<std::string> Connection::read_line(std::size_t max_line_bytes) {
    for (;;) {
        auto newline_pos = buffer_.find('\n', scanned_);
        if (newline_pos != std::string::npos) {
            std::string line(buffer_.data(), newline_pos);
            // The line may carry a passphrase (rotate/passwd); don't leave it behind.
            sodium_memzero(buffer_.data(), newline_pos + 1);
            buffer_.erase(0, newline_pos + 1);
            scanned_ = 0;
            return line;
        }
        scanned_ = buffer_.size();
        if (buffer_.size() > max_line_bytes) {
            return std::nullopt;
        }

        char chunk[4096];
        ssize_t n = read_retry(fd_, chunk, sizeof(chunk));
        if (n < 0) {
            timed_out_ = errno == EAGAIN || errno == EWOULDBLOCK;
            return std::nullopt;
        }
        if (n == 0) {
            // EOF: discard any unterminated trailing partial line.
            return std::nullopt;
        }
        buffer_.append(chunk, static_cast<size_t>(n));
        sodium_memzero(chunk, static_cast<size_t>(n));
    }
}

bool Connection::write_line(const std::string& line) {
    // Reserved up front: a reallocation would leave an unzeroed copy of the line.
    std::string out;
    out.reserve(line.size() + 1);
    out.append(line).push_back('\n');

    size_t total = 0;
    while (total < out.size()) {
        // MSG_NOSIGNAL: a peer that hung up is an error return, not a SIGPIPE that kills the client.
        ssize_t n = ::send(fd_, out.data() + total, out.size() - total, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            timed_out_ = errno == EAGAIN || errno == EWOULDBLOCK;
            sodium_memzero(out.data(), out.size());
            return false;
        }
        total += static_cast<size_t>(n);
    }
    sodium_memzero(out.data(), out.size());
    return true;
}

uid_t Connection::peer_uid() const {
    struct ucred cred{};
    socklen_t len = sizeof(cred);
    if (::getsockopt(fd_, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
        throw_errno("getsockopt(SO_PEERCRED) failed");
    }
    return cred.uid;
}

void Connection::set_timeout(int seconds) {
    struct timeval limit{};
    limit.tv_sec = seconds;
    if (::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit)) != 0 ||
        ::setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit)) != 0) {
        throw_errno("setsockopt(SO_RCVTIMEO/SO_SNDTIMEO) failed");
    }
}

Listener::Listener(const std::string& path) : fd_(-1), path_(path) {
    struct stat existing{};
    if (::lstat(path_.c_str(), &existing) == 0) {
        if (connect_unix(path_)) {
            throw std::runtime_error("daemon already running at " + path_);
        }
        if (!S_ISSOCK(existing.st_mode)) {
            throw std::runtime_error(path_ + " exists and is not a socket; refusing to remove it");
        }
        if (::unlink(path_.c_str()) != 0 && errno != ENOENT) {
            throw_errno("unlink stale socket '" + path_ + "'");
        }
    }

    std::optional<sockaddr_un> addr = unix_address(path_);
    if (!addr) {
        throw std::runtime_error("socket path too long: " + path_);
    }

    fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd_ < 0) {
        throw_errno("socket() failed");
    }

    auto fail = [this](const char* operation, int saved_errno, bool remove_socket) {
        ::close(fd_);
        if (remove_socket) {
            ::unlink(path_.c_str());
        }
        throw std::runtime_error(std::string(operation) + "(" + path_ + ") failed: " + std::strerror(saved_errno));
    };

    // Bind under a restrictive umask so the socket is never briefly group/other
    // accessible before the chmod lands.
    mode_t old_umask = ::umask(0077);
    int bind_result = ::bind(fd_, reinterpret_cast<const sockaddr*>(&*addr), sizeof(*addr));
    int bind_errno = errno;
    ::umask(old_umask);
    if (bind_result != 0) {
        fail("bind", bind_errno, false);
    }

    if (::chmod(path_.c_str(), 0600) != 0) {
        fail("chmod", errno, true);
    }

    struct stat bound{};
    if (::lstat(path_.c_str(), &bound) != 0) {
        fail("stat", errno, true);
    }
    bound_dev_ = bound.st_dev;
    bound_ino_ = bound.st_ino;

    if (::listen(fd_, SOMAXCONN) != 0) {
        fail("listen", errno, true);
    }
}

Listener::~Listener() {
    if (fd_ >= 0) {
        ::close(fd_);
    }
    unlink_if_same_inode(path_.c_str(), bound_dev_, bound_ino_);
}

std::optional<Connection> Listener::accept() {
    int client_fd;
    do {
        client_fd = ::accept(fd_, nullptr, nullptr);
    } while (client_fd < 0 && errno == EINTR);

    if (client_fd < 0) {
        return std::nullopt;
    }
    return Connection(client_fd);
}

std::optional<Connection> connect_unix(const std::string& path) {
    std::optional<sockaddr_un> addr = unix_address(path);
    if (!addr) {
        return std::nullopt;
    }
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return std::nullopt;
    }

    int rc;
    do {
        rc = ::connect(fd, reinterpret_cast<const sockaddr*>(&*addr), sizeof(*addr));
    } while (rc < 0 && errno == EINTR);

    if (rc < 0) {
        ::close(fd);
        return std::nullopt;
    }
    return Connection(fd);
}

void unlink_if_same_inode(const char* path, dev_t dev, ino_t ino) {
    struct stat current{};
    if (ino != 0 && ::lstat(path, &current) == 0 && current.st_dev == dev && current.st_ino == ino) {
        ::unlink(path);
    }
}

}  // namespace secretov
