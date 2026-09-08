#pragma once

#include <sys/types.h>

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

    std::optional<std::string> read_line();
    bool write_line(const std::string& line);
    uid_t peer_uid() const;

private:
    int fd_;
    std::string buffer_;
};

// Unix socket listener. The only transport secretov has or plans to have.
class Listener {
public:
    explicit Listener(const std::string& path);
    ~Listener();

    Listener(const Listener&) = delete;
    Listener& operator=(const Listener&) = delete;

    std::optional<Connection> accept();

private:
    int fd_;
    std::string path_;
};

std::optional<Connection> connect_unix(const std::string& path);

}  // namespace secretov
