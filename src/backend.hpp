#pragma once

// The seam between the manifest front end (exec, get, set, delete, TUI) and
// where secrets live. Paths are resolved references (a local store key today);
// values are opaque strings. See docs/backends-design.md.

#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "client.hpp"
#include "manifest.hpp"
#include "paths.hpp"

namespace secretov {

struct BackendError : std::runtime_error {
    enum class Kind { NotFound, Denied, NoCredentials, Unreachable, PendingDeletion };
    BackendError(Kind kind, const std::string& what) : std::runtime_error(what), kind(kind) {}
    Kind kind;
    bool maybe_applied = false;   // Unreachable after the request was sent
    std::string pending_until;    // PendingDeletion only
    // Unreachable detail the TUI words its status bar from.
    bool timed_out = false;       // sent, or tried to send, and got no reply within timeout_seconds
    int timeout_seconds = 0;
    bool not_running = false;     // nothing listens at the daemon socket
};

struct Fetched {
    std::map<std::string, std::string> values;
    std::map<std::string, BackendError> failures;  // NotFound, Denied, PendingDeletion
};

class Backend {
public:
    virtual ~Backend() = default;
    // Attempts every path: per-path NotFound, Denied and PendingDeletion land
    // in failures; anything else throws and aborts the batch.
    virtual Fetched get_many(const std::vector<std::string>& paths) = 0;
    virtual void set(const std::string& path, std::string_view value) = 0;  // create or replace
    virtual std::optional<std::string> remove(const std::string& path) = 0;  // AWS: DeletionDate
    virtual void restore(const std::string& path);  // AWS only; the default throws logic_error
};

// aws and gcp throw "backend 'aws' not compiled in (rebuild with ...)".
std::unique_ptr<Backend> open_backend(const BackendConfig& config, const Paths& paths);

// DaemonClient::request with daemon failures typed as BackendError: no reply
// is Unreachable, "not found" NotFound, "invalid token" NoCredentials.
nlohmann::json local_request(const DaemonClient& client, const std::string& op, const std::string& key = "",
                             std::optional<std::string_view> value = std::nullopt);

}  // namespace secretov
