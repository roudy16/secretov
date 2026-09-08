#include "transport.hpp"

#include <sys/socket.h>
#include <sys/stat.h>
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

// Cap unterminated line growth; a peer that never sends '\n' gets dropped.
constexpr std::size_t kMaxLineBytes = 1 << 20;  // 1 MiB

// EINTR-safe read; -1 on real error, 0 on EOF, >0 bytes read otherwise.
ssize_t read_retry(int fd, char* buf, size_t len) {
    ssize_t n;
    do {
        n = ::read(fd, buf, len);
    } while (n < 0 && errno == EINTR);
    return n;
}

}  // namespace

Connection::Connection(int fd) : fd_(fd) {}

Connection::~Connection() {
    if (fd_ >= 0) {
        ::close(fd_);
    }
}

Connection::Connection(Connection&& other) noexcept
    : fd_(other.fd_), buffer_(std::move(other.buffer_)) {
    other.fd_ = -1;
}

Connection& Connection::operator=(Connection&& other) noexcept {
    if (this != &other) {
        if (fd_ >= 0) {
            ::close(fd_);
        }
        fd_ = other.fd_;
        buffer_ = std::move(other.buffer_);
        other.fd_ = -1;
    }
    return *this;
}

std::optional<std::string> Connection::read_line() {
    for (;;) {
        auto newline_pos = buffer_.find('\n');
        if (newline_pos != std::string::npos) {
            std::string line = buffer_.substr(0, newline_pos);
            buffer_.erase(0, newline_pos + 1);
            return line;
        }
        if (buffer_.size() > kMaxLineBytes) {
            return std::nullopt;
        }

        char chunk[4096];
        ssize_t n = read_retry(fd_, chunk, sizeof(chunk));
        if (n < 0) {
            return std::nullopt;
        }
        if (n == 0) {
            // EOF: discard any unterminated trailing partial line.
            return std::nullopt;
        }
        buffer_.append(chunk, static_cast<size_t>(n));
    }
}

bool Connection::write_line(const std::string& line) {
    std::string out = line;
    out.push_back('\n');

    size_t total = 0;
    while (total < out.size()) {
        ssize_t n = ::write(fd_, out.data() + total, out.size() - total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        total += static_cast<size_t>(n);
    }
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

Listener::Listener(const std::string& path) : fd_(-1), path_(path) {
    fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd_ < 0) {
        throw_errno("socket() failed");
    }

    ::unlink(path_.c_str());

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
    ::unlink(path_.c_str());
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

}  // namespace secretov
