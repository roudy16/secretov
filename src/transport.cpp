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

// erase() in read_line slides the unread tail forward and leaves a stale copy
// of it past size(); zero the whole allocation, not just the live bytes.
void scrub_whole_buffer(std::string& buffer) {
    buffer.resize(buffer.capacity());
    sodium_memzero(buffer.data(), buffer.size());
}

}  // namespace

Connection::Connection(int fd) : fd_(fd) { buffer_.reserve(kInitialBufferBytes); }

Connection::~Connection() {
    scrub_whole_buffer(buffer_);
    if (fd_ >= 0) {
        ::close(fd_);
    }
}

Connection::Connection(Connection&& other) noexcept
    : fd_(other.fd_), buffer_(std::move(other.buffer_)), scanned_(other.scanned_), timed_out_(other.timed_out_) {
    other.fd_ = -1;
}

Connection& Connection::operator=(Connection&& other) noexcept {
    if (this != &other) {
        if (fd_ >= 0) {
            ::close(fd_);
        }
        scrub_whole_buffer(buffer_);
        fd_ = other.fd_;
        buffer_ = std::move(other.buffer_);
        scanned_ = other.scanned_;
        timed_out_ = other.timed_out_;
        other.fd_ = -1;
    }
    return *this;
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
        ssize_t n = ::write(fd_, out.data() + total, out.size() - total);
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

    fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd_ < 0) {
        throw_errno("socket() failed");
    }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (path_.size() >= sizeof(addr.sun_path)) {
        ::close(fd_);
        throw std::runtime_error("socket path too long: " + path_);
    }
    std::strncpy(addr.sun_path, path_.c_str(), sizeof(addr.sun_path) - 1);

    // Bind under a restrictive umask so the socket is never briefly group/other
    // accessible before the chmod lands.
    mode_t old_umask = ::umask(0077);

    if (::bind(fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        std::string err = std::string("bind(") + path_ + ") failed: " + std::strerror(errno);
        ::umask(old_umask);
        ::close(fd_);
        throw std::runtime_error(err);
    }

    if (::chmod(path_.c_str(), 0600) != 0) {
        std::string err = std::string("chmod(") + path_ + ") failed: " + std::strerror(errno);
        ::umask(old_umask);
        ::close(fd_);
        ::unlink(path_.c_str());
        throw std::runtime_error(err);
    }
    ::umask(old_umask);

    struct stat bound{};
    if (::lstat(path_.c_str(), &bound) != 0) {
        std::string err = std::string("stat(") + path_ + ") failed: " + std::strerror(errno);
        ::close(fd_);
        ::unlink(path_.c_str());
        throw std::runtime_error(err);
    }
    bound_dev_ = bound.st_dev;
    bound_ino_ = bound.st_ino;

    if (::listen(fd_, SOMAXCONN) != 0) {
        std::string err = std::string("listen(") + path_ + ") failed: " + std::strerror(errno);
        ::close(fd_);
        ::unlink(path_.c_str());
        throw std::runtime_error(err);
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
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return std::nullopt;
    }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (path.size() >= sizeof(addr.sun_path)) {
        ::close(fd);
        return std::nullopt;
    }
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

    int rc;
    do {
        rc = ::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
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
