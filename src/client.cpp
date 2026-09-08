#include "client.hpp"

#include <sodium.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "manifest.hpp"
#include "paths.hpp"
#include "protocol.hpp"
#include "store.hpp"
#include "transport.hpp"

namespace secretov {

DaemonClient::DaemonClient(const Paths& paths) : socket_path_(paths.socket) {
    token_ = rstrip(read_file_string(paths.token));
    if (token_.empty()) {
        throw std::runtime_error("token file '" + paths.token + "' is empty");
    }
}

nlohmann::json DaemonClient::send(const nlohmann::json& req) const {
    nlohmann::json full = req;
    full["token"] = token_;
    std::optional<Connection> conn = connect_unix(socket_path_);
    if (!conn) {
        throw std::runtime_error("daemon not running at " + socket_path_ + " ?");
    }
    if (!conn->write_line(full.dump())) {
        throw std::runtime_error("failed to send request to daemon");
    }
    auto line = conn->read_line();
    if (!line) {
        throw std::runtime_error("daemon closed connection without responding");
    }
    nlohmann::json resp;
    try {
        resp = nlohmann::json::parse(*line);
    } catch (const nlohmann::json::exception&) {
        throw std::runtime_error("malformed response from daemon");
    }
    return resp;
}

nlohmann::json DaemonClient::request_raw(const nlohmann::json& req) const {
    nlohmann::json resp = send(req);
    if (!resp.value("ok", false)) {
        throw std::runtime_error(resp.value("error", std::string("request failed")));
    }
    return resp;
}

nlohmann::json DaemonClient::request(const std::string& op, const std::string& key,
                                     const std::optional<std::string>& value) const {
    nlohmann::json req{{"op", op}};
    if (!key.empty()) req["key"] = key;
    if (value) req["value"] = *value;
    return request_raw(req);
}

namespace {

// Read whole stdin, strip a single trailing newline. Keeps secrets out of argv.
std::string read_stdin_value() {
    std::stringstream ss;
    ss << std::cin.rdbuf();
    std::string value = ss.str();
    if (!value.empty() && value.back() == '\n') value.pop_back();
    if (!value.empty() && value.back() == '\r') value.pop_back();
    return value;
}

std::map<std::string, std::string> fetch_prefix(const DaemonClient& client, const std::string& prefix) {
    nlohmann::json resp = client.request("getprefix", prefix);
    return resp.value("values", std::map<std::string, std::string>{});
}

std::string cwd() {
    std::error_code ec;
    std::filesystem::path p = std::filesystem::current_path(ec);
    if (ec) {
        throw std::runtime_error("getcwd failed: " + ec.message());
    }
    return p.string();
}

// --- scope resolution (see DESIGN.md "Scopes") -------------------------------

struct ScopeArgs {
    std::optional<std::string> project;
    std::optional<std::string> env;
};

// Consumes -p/--project and -e/--env at argv[i]; returns false if argv[i] is
// neither. Advances i past a consumed value.
bool take_scope_arg(int argc, char** argv, int& i, ScopeArgs& scope) {
    std::string arg = argv[i];
    bool is_p = arg == "-p" || arg == "--project";
    bool is_e = arg == "-e" || arg == "--env";
    if (!is_p && !is_e) return false;
    if (i + 1 >= argc) throw std::runtime_error(arg + " requires a value");
    (is_p ? scope.project : scope.env) = argv[++i];
    return true;
}

// -p: registry lookup (must be registered); otherwise nearest manifest from cwd.
Manifest resolve_manifest(const Paths& paths, const ScopeArgs& scope) {
    if (scope.project) {
        std::optional<std::string> root = registry_project_root(paths.registry, *scope.project);
        if (!root) {
            throw std::runtime_error("project '" + *scope.project + "' is not in " + paths.registry +
                                     "; add it there or run from inside the project");
        }
        Manifest m = load_manifest(*root + "/" + kManifestFileName);
        if (m.project != *scope.project) {
            throw std::runtime_error("manifest " + m.path + " names project '" + m.project +
                                     "' but registry entry is '" + *scope.project + "'");
        }
        return m;
    }
    std::optional<std::string> found = find_manifest_upward(cwd());
    if (!found) {
        throw std::runtime_error(std::string("no ") + kManifestFileName +
                                 " found from the current directory upward; pass -p NAME");
    }
    return load_manifest(*found);
}

std::string resolve_env(const ScopeArgs& scope, const Manifest* manifest) {
    if (scope.env) return *scope.env;
    if (const char* v = std::getenv(kEnvOverrideVar); v && *v) return v;
    if (manifest && manifest->default_env) return *manifest->default_env;
    throw std::runtime_error(std::string("no environment: pass -e ENV, set ") + kEnvOverrideVar +
                             ", or add default_env to the manifest");
}

struct ResolvedScope {
    std::string env;
    std::string project;
};

// (env, project) for a scope flag pair. -p names the project outright and the
// manifest is optional (only default_env needs it); otherwise the nearest
// manifest from cwd supplies the project.
ResolvedScope resolve_scope(const Paths& paths, const ScopeArgs& scope) {
    std::optional<Manifest> manifest;
    std::string project;
    if (scope.project) {
        project = *scope.project;
        if (std::optional<std::string> root = registry_project_root(paths.registry, project)) {
            manifest = load_manifest(*root + "/" + kManifestFileName);
        }
    } else {
        manifest = resolve_manifest(paths, scope);
        project = manifest->project;
    }
    return {resolve_env(scope, manifest ? &*manifest : nullptr), project};
}

// Plaintext vars for an env; empty when it declares none. Unlike entries_for
// a missing env is not an error here — entries_for has already vetted it.
const KeyValues& vars_for(const Manifest& m, const std::string& env) {
    static const KeyValues kNone;
    auto it = m.vars.find(env);
    return it == m.vars.end() ? kNone : it->second;
}

const std::vector<SecretEntry>& entries_for(const Manifest& m, const std::string& env) {
    auto it = m.envs.find(env);
    if (it == m.envs.end()) {
        throw std::runtime_error("environment '" + env + "' not found in " + m.path);
    }
    return it->second;
}

}  // namespace

int cmd_init() {
    Paths paths = resolve_paths();
    try {
        std::string passphrase = read_passphrase("Passphrase: ");
        if (::isatty(STDIN_FILENO)) {
            std::string confirm = read_passphrase("Confirm passphrase: ");
            if (passphrase != confirm) {
                std::cerr << "secretov: passphrases do not match\n";
                return 1;
            }
        }

        ensure_parent_dir(paths.store);
        Store::create(paths.store, passphrase, static_cast<std::uint64_t>(std::time(nullptr)));

        unsigned char raw[32];
        randombytes_buf(raw, sizeof(raw));
        char hex[sizeof(raw) * 2 + 1];
        sodium_bin2hex(hex, sizeof(hex), raw, sizeof(raw));
        sodium_memzero(raw, sizeof(raw));
        write_file_atomic(paths.token, hex, 0600);
        sodium_memzero(hex, sizeof(hex));
    } catch (const std::exception& e) {
        std::cerr << "secretov: init failed: " << e.what() << "\n";
        return 1;
    }
    std::cout << "secretov initialized\n"
              << "  store: " << paths.store << "\n"
              << "  token: " << paths.token << "\n"
              << "  socket: " << paths.socket << "\n"
              << "Start the daemon with: secretov daemon\n";
    return 0;
}

int cmd_get(const std::string& key) {
    Paths paths = resolve_paths();
    try {
        nlohmann::json resp = DaemonClient(paths).request("get", key);
        std::cout << resp.value("value", std::string{}) << "\n";
    } catch (const std::exception& e) {
        std::cerr << "secretov: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

int cmd_set(int argc, char** argv) {
    static const char* kUsage =
        "usage: secretov set KEY [-p NAME] [-e ENV]   (value read from stdin)\n";
    Paths paths = resolve_paths();
    ScopeArgs scope;
    std::string name;
    bool name_given = false;
    try {
        for (int i = 0; i < argc; ++i) {
            std::string arg = argv[i];
            if (take_scope_arg(argc, argv, i, scope)) continue;
            // A second positional would be an argv VALUE, which must never be
            // accepted: it would leak the secret via /proc/<pid>/cmdline.
            if (name_given || arg.empty() || arg[0] == '-') {
                throw std::runtime_error("unexpected argument '" + arg + "'");
            }
            name = arg;
            name_given = true;
        }
        if (!name_given) throw std::runtime_error("missing KEY");
    } catch (const std::exception& e) {
        std::cerr << "secretov set: " << e.what() << "\n" << kUsage;
        return 2;
    }
    try {
        std::string key = name;
        if (scope.project || scope.env) {
            ResolvedScope resolved = resolve_scope(paths, scope);
            key = scoped_key(resolved.env, resolved.project, name);
        }
        DaemonClient(paths).request("set", key, read_stdin_value());
    } catch (const std::exception& e) {
        std::cerr << "secretov: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

int cmd_list(int argc, char** argv) {
    Paths paths = resolve_paths();
    try {
        ScopeArgs scope;
        for (int i = 0; i < argc; ++i) {
            if (!take_scope_arg(argc, argv, i, scope)) {
                std::cerr << "usage: secretov list [-p NAME] [-e ENV]\n";
                return 2;
            }
        }
        std::string prefix;
        if (scope.project || scope.env) {
            ResolvedScope resolved = resolve_scope(paths, scope);
            prefix = scope_prefix(resolved.env, resolved.project);
        }
        nlohmann::json resp = DaemonClient(paths).request("list");
        for (const auto& key : resp.value("keys", std::vector<std::string>{})) {
            if (key.compare(0, prefix.size(), prefix) == 0) std::cout << key << "\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "secretov: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

int cmd_delete(const std::string& key) {
    Paths paths = resolve_paths();
    try {
        DaemonClient(paths).request("delete", key);
    } catch (const std::exception& e) {
        std::cerr << "secretov: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

int cmd_rotate() {
    Paths paths = resolve_paths();
    try {
        std::string pass = read_passphrase("Current passphrase: ");
        DaemonClient(paths).request_raw(nlohmann::json{{"op", "rotate"}, {"old", pass}});
        std::cout << "rotated encryption key\n";
    } catch (const std::exception& e) {
        std::cerr << "secretov: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

int cmd_passwd() {
    Paths paths = resolve_paths();
    try {
        std::string old_pass = read_passphrase("Current passphrase: ");
        std::string new_pass = read_passphrase("New passphrase: ");
        if (::isatty(STDIN_FILENO)) {
            std::string confirm = read_passphrase("Confirm new passphrase: ");
            if (new_pass != confirm) {
                std::cerr << "secretov: passphrases do not match\n";
                return 1;
            }
        }
        DaemonClient(paths).request_raw(nlohmann::json{{"op", "passwd"}, {"old", old_pass}, {"new", new_pass}});
        std::cout << "passphrase changed\n";
    } catch (const std::exception& e) {
        std::cerr << "secretov: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

int cmd_exec(int argc, char** argv) {
    static const char* kUsage =
        "usage: secretov exec [-p NAME] [-e ENV] [--dry-run] [--secret KEY[=ENVVAR]]... -- PROG [ARGS...]\n";
    ScopeArgs scope;
    bool dry_run = false;
    std::vector<std::pair<std::string, std::string>> raw;  // (key, envvar)
    int i = 0;
    try {
        for (; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--") {
                ++i;
                break;
            }
            if (take_scope_arg(argc, argv, i, scope)) continue;
            if (arg == "--dry-run") {
                dry_run = true;
            } else if (arg == "--secret") {
                if (i + 1 >= argc) throw std::runtime_error("--secret requires KEY[=ENVVAR]");
                std::string spec = argv[++i];
                std::size_t eq = spec.find('=');
                if (eq == std::string::npos) {
                    raw.emplace_back(spec, spec);
                } else {
                    raw.emplace_back(spec.substr(0, eq), spec.substr(eq + 1));
                }
            } else {
                throw std::runtime_error("unexpected argument '" + arg + "' before '--'");
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "secretov exec: " << e.what() << "\n" << kUsage;
        return 2;
    }
    if (i >= argc && !dry_run) {
        std::cerr << kUsage;
        return 2;
    }

    Paths paths = resolve_paths();
    try {
        // Raw-only invocations (--secret with no -p/-e) skip the manifest so
        // one-off keys work anywhere, including inside a project directory.
        std::vector<std::pair<std::string, std::string>> wanted;  // (envvar, key)
        KeyValues plain;                                          // (envvar, literal value)
        if (scope.project || scope.env || raw.empty()) {
            Manifest manifest = resolve_manifest(paths, scope);
            std::string env = resolve_env(scope, &manifest);
            for (const SecretEntry& e : entries_for(manifest, env)) {
                wanted.emplace_back(e.env_var, e.key);
            }
            plain = vars_for(manifest, env);
        }
        for (const auto& [key, envvar] : raw) wanted.emplace_back(envvar, key);

        if (dry_run) {
            // Manifest vars are plaintext in a committed file, so printing them
            // leaks nothing; secrets still show only their key.
            for (const auto& [envvar, value] : plain) std::cout << envvar << " = " << value << "\n";
            for (const auto& [envvar, key] : wanted) std::cout << envvar << " <- " << key << "\n";
            return 0;
        }

        // Plaintext first, so an explicit --secret on the command line wins
        // over a manifest var of the same name.
        for (const auto& [envvar, value] : plain) {
            if (::setenv(envvar.c_str(), value.c_str(), 1) != 0) {
                throw std::runtime_error("setenv '" + envvar + "' failed");
            }
        }

        // One getprefix per env/project/ group; keys without a '/' are fetched singly.
        DaemonClient client(paths);
        std::map<std::string, std::map<std::string, std::string>> by_prefix;
        std::vector<std::string> missing;
        for (const auto& [envvar, key] : wanted) {
            std::size_t slash = key.find_last_of('/');
            std::string value;
            if (slash == std::string::npos) {
                nlohmann::json resp = client.send(nlohmann::json{{"op", "get"}, {"key", key}});
                if (!resp.value("ok", false)) {
                    missing.push_back(key);
                    continue;
                }
                value = resp.value("value", std::string{});
            } else {
                std::string prefix = key.substr(0, slash + 1);
                auto group = by_prefix.find(prefix);
                if (group == by_prefix.end()) {
                    group = by_prefix.emplace(prefix, fetch_prefix(client, prefix)).first;
                }
                auto hit = group->second.find(key);
                if (hit == group->second.end()) {
                    missing.push_back(key);
                    continue;
                }
                value = hit->second;
            }
            if (::setenv(envvar.c_str(), value.c_str(), 1) != 0) {
                throw std::runtime_error("setenv '" + envvar + "' failed");
            }
        }
        if (!missing.empty()) {
            std::string list;
            for (const auto& k : missing) list += (list.empty() ? "" : ", ") + k;
            throw std::runtime_error("missing secrets: " + list);
        }
    } catch (const std::exception& e) {
        std::cerr << "secretov exec: " << e.what() << "\n";
        return 1;
    }

    ::execvp(argv[i], &argv[i]);
    std::cerr << "secretov exec: cannot run '" << argv[i] << "': " << std::strerror(errno) << "\n";
    return 1;
}

int cmd_import(int argc, char** argv) {
    static const char* kUsage = "usage: secretov import [FILE] [-p NAME] [-e ENV] [--overwrite]\n";
    ScopeArgs scope;
    bool overwrite = false;
    std::string file = ".env";
    bool file_given = false;
    try {
        for (int i = 0; i < argc; ++i) {
            std::string arg = argv[i];
            if (take_scope_arg(argc, argv, i, scope)) continue;
            if (arg == "--overwrite") {
                overwrite = true;
            } else if (!arg.empty() && arg[0] != '-' && !file_given) {
                file = arg;
                file_given = true;
            } else {
                throw std::runtime_error("unexpected argument '" + arg + "'");
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "secretov import: " << e.what() << "\n" << kUsage;
        return 2;
    }

    Paths paths = resolve_paths();
    try {
        // Manifest location: registry root for -p; else nearest from cwd; a
        // -p that is neither registered nor found gets a new manifest in cwd.
        std::string manifest_path;
        std::string project;
        if (scope.project) {
            project = *scope.project;
            if (auto root = registry_project_root(paths.registry, project)) {
                manifest_path = *root + "/" + kManifestFileName;
            } else if (auto found = find_manifest_upward(cwd())) {
                manifest_path = *found;
            } else {
                manifest_path = cwd() + "/" + kManifestFileName;
            }
        } else {
            std::optional<std::string> found = find_manifest_upward(cwd());
            if (!found) {
                throw std::runtime_error(std::string("no ") + kManifestFileName +
                                         " found from the current directory upward; pass -p NAME to create one here");
            }
            manifest_path = *found;
        }
        std::optional<Manifest> manifest;
        std::string manifest_text;
        if (::access(manifest_path.c_str(), F_OK) == 0) {
            manifest_text = read_file_string(manifest_path);
            manifest = parse_manifest(manifest_text, manifest_path);
            if (scope.project && manifest->project != project) {
                throw std::runtime_error("manifest " + manifest_path + " names project '" + manifest->project +
                                         "', not '" + project + "'");
            }
            project = manifest->project;
        }
        std::string env = resolve_env(scope, manifest ? &*manifest : nullptr);

        KeyValues pairs = parse_dotenv(read_file_string(file));
        if (pairs.empty()) throw std::runtime_error("nothing to import from " + file);

        DaemonClient client(paths);
        std::map<std::string, std::string> existing = fetch_prefix(client, scope_prefix(env, project));
        std::vector<std::string> collisions;
        KeyValues name_to_var;
        for (const auto& [var, value] : pairs) {
            std::string key = scoped_key(env, project, var);
            if (existing.count(key)) collisions.push_back(key);
            name_to_var.emplace_back(var, var);
        }
        if (!collisions.empty() && !overwrite) {
            std::string list;
            for (const auto& k : collisions) list += "\n  " + k;
            throw std::runtime_error("already in store (pass --overwrite to replace):" + list);
        }

        // Prove the manifest edit before touching the store.
        std::string new_text = manifest_with_entries(manifest_text, project, env, name_to_var);

        for (const auto& [var, value] : pairs) {
            client.request("set", scoped_key(env, project, var), value);
        }
        if (new_text != manifest_text) write_file_atomic(manifest_path, new_text, 0644);

        std::cout << "imported " << pairs.size() << " secret(s) into " << scope_prefix(env, project);
        if (!collisions.empty()) std::cout << " (" << collisions.size() << " overwritten)";
        std::cout << "\nmanifest: " << manifest_path << "\n";
    } catch (const std::exception& e) {
        std::cerr << "secretov import: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

}  // namespace secretov
