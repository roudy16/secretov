#pragma once

#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

#include "paths.hpp"

namespace secretov {

// No reply from the daemon: not running, busy past the reply timeout, or hung
// up. Daemon-side errors stay plain std::runtime_error.
struct DaemonUnreachable : std::runtime_error {
    enum class Stage {
        NotRunning,  // nothing listens at the socket
        NotSent,     // connected, but the request never left
        Sent,        // the request is in the daemon's queue: it may still be applied
    };
    DaemonUnreachable(const std::string& what, Stage at) : std::runtime_error(what), stage(at) {}
    Stage stage;
};

// Talks to the daemon over a fresh connection per request (the daemon serves
// one connection at a time and blocks on read, so a persistent connection
// from one client starves every other client). Loads the token from
// paths.token at construction; throws if it is missing/empty.
class DaemonClient {
public:
    explicit DaemonClient(const Paths& paths);

    // Connect, send one request, return the parsed response. Throws
    // DaemonUnreachable on transport failure (including no reply within the
    // timeout) and std::runtime_error on a malformed response.
    nlohmann::json send(const nlohmann::json& req) const;

    // Same, but throws the daemon's error message on a non-ok reply. Adds
    // token/op/key/value to the request.
    // The value's copies in the request are zeroed once it is sent.
    nlohmann::json request(const std::string& op, const std::string& key = "",
                           std::optional<std::string_view> value = std::nullopt) const;
    // Same, but for a caller-built request (e.g. passwd's extra fields);
    // adds the token.
    nlohmann::json request_raw(const nlohmann::json& req) const;

    const std::string& socket_path() const { return socket_path_; }

private:
    std::string socket_path_;
    std::string token_;
};

// Each returns a process exit code. Paths are resolved from the environment.
int cmd_init();
int cmd_get(const std::string& key);
int cmd_set(int argc, char** argv);     // KEY [-p NAME] [-e ENV]; value read from stdin
int cmd_list(int argc, char** argv);    // [-p NAME] [-e ENV]
int cmd_delete(const std::string& key);
int cmd_rotate();
int cmd_passwd();  // reads current + new passphrase from tty/stdin
int cmd_exec(int argc, char** argv);    // argv/argc positioned at args after "exec"
int cmd_import(int argc, char** argv);  // [FILE] [-p NAME] [-e ENV] [--overwrite]

}  // namespace secretov
