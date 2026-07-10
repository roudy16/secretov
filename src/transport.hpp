#pragma once

#include <sys/types.h>

#include <memory>
#include <optional>
#include <string>

namespace secretov {

class Connection {
public:
    virtual ~Connection() = default;
    virtual std::optional<std::string> read_line() = 0;
    virtual bool write_line(const std::string& line) = 0;
    virtual uid_t peer_uid() const = 0;
};

class Listener {
public:
    virtual ~Listener() = default;
    virtual std::unique_ptr<Connection> accept() = 0;
};

class UnixSocketConnection : public Connection {
public:
    explicit UnixSocketConnection(int fd);
    ~UnixSocketConnection() override;

    std::optional<std::string> read_line() override;
    bool write_line(const std::string& line) override;
    uid_t peer_uid() const override;

private:
    int fd_;
    std::string buffer_;
};

class UnixSocketListener : public Listener {
public:
    explicit UnixSocketListener(const std::string& path);
    ~UnixSocketListener() override;

    std::unique_ptr<Connection> accept() override;

private:
    int fd_;
    std::string path_;
};

std::unique_ptr<Connection> connect_unix(const std::string& path);

}  // namespace secretov
