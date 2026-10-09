#include "backend.hpp"

#include <algorithm>
#include <utility>

#include "protocol.hpp"

namespace secretov {

void Backend::restore(const std::string&) { throw std::logic_error("this backend cannot restore secrets"); }

nlohmann::json local_request(const DaemonClient& client, const std::string& op, const std::string& key,
                             std::optional<std::string_view> value) {
    try {
        return client.request(op, key, value);
    } catch (const DaemonUnreachable& e) {
        BackendError error(BackendError::Kind::Unreachable, e.what());
        error.maybe_applied = e.stage == DaemonUnreachable::Stage::Sent;
        error.timed_out = e.timed_out;
        error.timeout_seconds = e.timeout_seconds;
        error.not_running = e.stage == DaemonUnreachable::Stage::NotRunning;
        throw error;
    } catch (const std::runtime_error& e) {
        std::string_view message = e.what();
        if (message == kErrNotFound) throw BackendError(BackendError::Kind::NotFound, e.what());
        if (message == kErrInvalidToken) throw BackendError(BackendError::Kind::NoCredentials, e.what());
        throw;
    }
}

namespace {

// Moves a JSON string out, so no second copy of the value stays behind in the reply.
std::string take_string(nlohmann::json& holder) {
    return holder.is_string() ? std::move(holder.get_ref<std::string&>()) : std::string{};
}

class LocalBackend : public Backend {
public:
    explicit LocalBackend(DaemonClient client) : client_(std::move(client)) {}

    // One getprefix per env/project/ prefix holding several of the paths; a
    // lone path (or one without a '/') is fetched singly.
    Fetched get_many(const std::vector<std::string>& paths) override {
        std::map<std::string, std::vector<std::string>> by_prefix;  // "" groups paths without a '/'
        for (const std::string& path : paths) {
            std::size_t slash = path.find_last_of('/');
            std::vector<std::string>& group = by_prefix[slash == std::string::npos ? "" : path.substr(0, slash + 1)];
            if (std::find(group.begin(), group.end(), path) == group.end()) group.push_back(path);
        }
        Fetched fetched;
        for (const auto& [prefix, group] : by_prefix) {
            bool batched = !prefix.empty() && group.size() > 1;
            std::map<std::string, std::string> scope;
            if (batched) {
                nlohmann::json resp = local_request(client_, "getprefix", prefix);
                for (auto& [key, value] : resp["values"].items()) scope.emplace(key, take_string(value));
            }
            for (const std::string& path : group) {
                try {
                    if (!batched) {
                        nlohmann::json resp = local_request(client_, "get", path);
                        fetched.values.emplace(path, take_string(resp["value"]));
                    } else if (auto hit = scope.find(path); hit != scope.end()) {
                        fetched.values.emplace(path, std::move(hit->second));
                    } else {
                        throw BackendError(BackendError::Kind::NotFound, kErrNotFound);
                    }
                } catch (const BackendError& e) {
                    if (e.kind != BackendError::Kind::NotFound) throw;
                    fetched.failures.emplace(path, e);
                }
            }
            for (auto& [key, leftover] : scope) wipe(leftover);  // the scope's other values
        }
        return fetched;
    }

    void set(const std::string& path, std::string_view value) override { local_request(client_, "set", path, value); }

    std::optional<std::string> remove(const std::string& path) override {
        local_request(client_, "delete", path);
        return std::nullopt;
    }

private:
    DaemonClient client_;
};

}  // namespace

std::unique_ptr<Backend> open_backend(const BackendConfig& config, const Paths& paths) {
    switch (config.type) {
        case BackendType::Local:
            try {
                return std::make_unique<LocalBackend>(DaemonClient(paths));
            } catch (const std::runtime_error& e) {
                throw BackendError(BackendError::Kind::NoCredentials, e.what());
            }
        case BackendType::Aws:
            throw std::runtime_error("backend 'aws' not compiled in (rebuild with -DSECRETOV_BACKEND_AWS=ON)");
        case BackendType::Gcp:
            throw std::runtime_error("backend 'gcp' not compiled in (rebuild with -DSECRETOV_BACKEND_GCP=ON)");
    }
    throw std::logic_error("unknown backend type");
}

}  // namespace secretov
