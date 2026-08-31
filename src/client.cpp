#include "client.hpp"

#include <sodium.h>
#include <unistd.h>

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <ctime>
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

std::string load_token(const Paths& paths) {
    std::string token = rstrip(read_file_string(paths.token));
    if (token.empty()) {
        throw std::runtime_error("token file '" + paths.token + "' is empty");
    }
    return token;
}

// Connect, send one request, return the parsed response. Throws on I/O trouble.
nlohmann::json send_request(const Paths& paths, const nlohmann::json& req) {
    std::unique_ptr<Connection> conn = connect_unix(paths.socket);
    if (!conn) {
        throw std::runtime_error("daemon not running at " + paths.socket + " ?");
    }
    if (!conn->write_line(req.dump())) {
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

// Send a request and, on a non-ok response, throw its error message.
nlohmann::json request_or_throw(const Paths& paths, const nlohmann::json& req) {
    nlohmann::json resp = send_request(paths, req);
    if (!resp.value("ok", false)) {
        throw std::runtime_error(resp.value("error", std::string("request failed")));
    }
    return resp;
}

nlohmann::json request_or_throw(const Paths& paths, const std::string& token, const std::string& op,
                                const std::string& key, const std::optional<std::string>& value) {
    nlohmann::json req{{"token", token}, {"op", op}};
    if (!key.empty()) req["key"] = key;
    if (value) req["value"] = *value;
    return request_or_throw(paths, req);
}

std::map<std::string, std::string> fetch_prefix(const Paths& paths, const std::string& token,
                                                const std::string& prefix) {
    nlohmann::json resp = request_or_throw(paths, token, "getprefix", prefix, std::nullopt);
    return resp.value("values", std::map<std::string, std::string>{});
}

std::string cwd() {
    char buf[PATH_MAX];
    if (!::getcwd(buf, sizeof(buf))) {
        throw std::runtime_error(std::string("getcwd failed: ") + std::strerror(errno));
    }
    return buf;
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
        nlohmann::json resp = request_or_throw(paths, load_token(paths), "get", key, std::nullopt);
        std::cout << resp.value("value", std::string{}) << "\n";
    } catch (const std::exception& e) {
        std::cerr << "secretov: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

int cmd_set(const std::string& key) {
    Paths paths = resolve_paths();
    try {
        std::string token = load_token(paths);
        request_or_throw(paths, token, "set", key, read_stdin_value());
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
            // -p alone needs no manifest: the prefix only needs the name.
            std::optional<Manifest> manifest;
            std::string project;
            if (scope.project) {
                project = *scope.project;
                if (auto root = registry_project_root(paths.registry, project)) {
                    manifest = load_manifest(*root + "/" + kManifestFileName);
                }
            } else {
                manifest = resolve_manifest(paths, scope);
                project = manifest->project;
            }
            prefix = scope_prefix(resolve_env(scope, manifest ? &*manifest : nullptr), project);
        }
        nlohmann::json resp = request_or_throw(paths, load_token(paths), "list", "", std::nullopt);
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
        request_or_throw(paths, load_token(paths), "delete", key, std::nullopt);
    } catch (const std::exception& e) {
        std::cerr << "secretov: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

int cmd_rotate() {
    Paths paths = resolve_paths();
    try {
        request_or_throw(paths, load_token(paths), "rotate", "", std::nullopt);
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
        request_or_throw(paths, nlohmann::json{{"token", load_token(paths)},
                                               {"op", "passwd"},
                                               {"old", old_pass},
                                               {"new", new_pass}});
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
        if (scope.project || scope.env || raw.empty()) {
            Manifest manifest = resolve_manifest(paths, scope);
            std::string env = resolve_env(scope, &manifest);
            for (const SecretEntry& e : entries_for(manifest, env)) {
                wanted.emplace_back(e.env_var, e.key);
            }
        }
        for (const auto& [key, envvar] : raw) wanted.emplace_back(envvar, key);

        if (dry_run) {
            for (const auto& [envvar, key] : wanted) std::cout << envvar << " <- " << key << "\n";
            return 0;
        }

        // One getprefix per env/project/ group; keys without a '/' are fetched singly.
        std::string token = load_token(paths);
        std::map<std::string, std::map<std::string, std::string>> by_prefix;
        std::vector<std::string> missing;
        for (const auto& [envvar, key] : wanted) {
            std::size_t slash = key.find_last_of('/');
            std::string value;
            if (slash == std::string::npos) {
                nlohmann::json resp = send_request(paths, nlohmann::json{{"token", token}, {"op", "get"}, {"key", key}});
                if (!resp.value("ok", false)) {
                    missing.push_back(key);
                    continue;
                }
                value = resp.value("value", std::string{});
            } else {
                std::string prefix = key.substr(0, slash + 1);
                auto group = by_prefix.find(prefix);
                if (group == by_prefix.end()) {
                    group = by_prefix.emplace(prefix, fetch_prefix(paths, token, prefix)).first;
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

        std::string token = load_token(paths);
        std::map<std::string, std::string> existing = fetch_prefix(paths, token, scope_prefix(env, project));
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
            request_or_throw(paths, token, "set", scoped_key(env, project, var), value);
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
