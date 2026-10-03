#pragma once

#include <sys/types.h>

#include <cstddef>
#include <optional>
#include <string>

namespace secretov {

// Unix socket connection. The only transport secretov has or plans to have.
class Connection {
public:
    explicit Connection(int fd);
    ~Connection();

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;
    Connection(Connection&& other) noexcept;
    Connection& operator=(Connection&& other) noexcept;

    // nullopt on EOF, error, or a line exceeding max_line_bytes (the peer is
    // then dropped). Consumed bytes are zeroed in the receive buffer, and the
    // whole allocation is zeroed on destruction.
    std::optional<std::string> read_line(std::size_t max_line_bytes);
    bool write_line(const std::string& line);
    uid_t peer_uid() const;

    // Bounds every later read/write call; a call that runs out fails, and
    // timed_out() then reports it. Throws if the socket refuses the option.
    void set_timeout(int seconds);
    bool timed_out() const { return timed_out_; }

private:
    int fd_;
    std::string buffer_;
    std::size_t scanned_ = 0;  // buffer_ prefix already searched for '\n'
    bool timed_out_ = false;
};

// Unix socket listener. The only transport secretov has or plans to have.
class Listener {
public:
    // Refuses (throws) when a live daemon already answers at `path`; only a
    // stale socket is unlinked.
    explicit Listener(const std::string& path);
    ~Listener();

    Listener(const Listener&) = delete;
    Listener& operator=(const Listener&) = delete;

    std::optional<Connection> accept();

    // Identity of the socket inode this listener bound; the path is unlinked
    // on exit only while it still names that inode.
    dev_t bound_dev() const { return bound_dev_; }
    ino_t bound_ino() const { return bound_ino_; }

private:
    int fd_;
    std::string path_;
    dev_t bound_dev_ = 0;
    ino_t bound_ino_ = 0;
};

std::optional<Connection> connect_unix(const std::string& path);

// Unlink `path` only if it still names the inode (dev, ino). Async-signal-safe
// (lstat + unlink only), so the daemon's signal handler can use it.
void unlink_if_same_inode(const char* path, dev_t dev, ino_t ino);

}  // namespace secretov
