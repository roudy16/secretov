#include "client.hpp"

#include <sodium.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "backend.hpp"
#include "manifest.hpp"
#include "paths.hpp"
#include "protocol.hpp"
#include "store.hpp"
#include "transport.hpp"

namespace secretov {

namespace {

// ponytail: fixed 64 MiB response cap (getprefix returns a whole scope's
// values); far above the daemon's 1 MiB request cap so a scope can outgrow
// any single value. Stream getprefix if scopes ever get this big.
constexpr std::size_t kMaxResponseBytes = 64 << 20;

constexpr std::size_t kRecommendedMinPassphraseChars = 12;

// The daemon serves one connection at a time, so a client that holds it would
// otherwise hang every other client forever. rotate/passwd run Argon2id.
constexpr int kReplyTimeoutSeconds = 5;
constexpr int kKdfReplyTimeoutSeconds = 60;

// Request fields that carry a secret value or passphrase.
void scrub_secret_fields(nlohmann::json& message) {
    for (const char* field : {"value", "old", "new", "token"}) {
        auto found = message.find(field);
        if (found != message.end() && found->is_string()) wipe(found->get_ref<std::string&>());
    }
}

class ScrubSecretFieldsOnExit {
public:
    explicit ScrubSecretFieldsOnExit(nlohmann::json& message) : message_(message) {}
    ~ScrubSecretFieldsOnExit() { scrub_secret_fields(message_); }
    ScrubSecretFieldsOnExit(const ScrubSecretFieldsOnExit&) = delete;
    ScrubSecretFieldsOnExit& operator=(const ScrubSecretFieldsOnExit&) = delete;

private:
    nlohmann::json& message_;
};

}  // namespace

DaemonClient::DaemonClient(const Paths& paths) : socket_path_(paths.socket) {
    token_ = rstrip(read_file_string(paths.token));
    if (token_.empty()) {
        throw std::runtime_error("token file '" + paths.token + "' is empty");
    }
}

std::string DaemonClient::serialize(const nlohmann::json& req) const {
    nlohmann::json full = req;
    full["token"] = token_;
    ScrubSecretFieldsOnExit scrub_full_on_exit(full);
    std::string request_line = full.dump();  // throws on invalid UTF-8
    // The daemon drops a longer line without a reply, which would read as "may still be applied".
    if (request_line.size() > kMaxRequestBytes) {
        std::size_t request_bytes = request_line.size();
        wipe(request_line);
        throw std::runtime_error("value too large: the request is " + std::to_string(request_bytes) +
                                 " bytes, the daemon's limit is " + std::to_string(kMaxRequestBytes));
    }
    return request_line;
}

nlohmann::json DaemonClient::send(const nlohmann::json& req) const {
    std::optional<Connection> conn = connect_unix(socket_path_);
    if (!conn) {
        throw DaemonUnreachable("daemon not running at " + socket_path_ + " ?", DaemonUnreachable::Stage::NotRunning);
    }
    std::string op = req.value("op", std::string{});
    int timeout_seconds = op == "rotate" || op == "passwd" ? kKdfReplyTimeoutSeconds : kReplyTimeoutSeconds;
    conn->set_timeout(timeout_seconds);
    std::string no_reply = "no reply within " + std::to_string(timeout_seconds) + " s";
    // Authenticate the daemon end before the token or any passphrase leaves us.
    uid_t daemon_uid = conn->peer_uid();
    if (daemon_uid != ::getuid()) {
        throw std::runtime_error("socket " + socket_path_ + " is served by uid " +
                                 std::to_string(daemon_uid) + ", not ours; refusing to send");
    }
    std::string request_line = serialize(req);
    bool sent = conn->write_line(request_line);
    wipe(request_line);
    if (!sent) {
        throw DaemonUnreachable(conn->timed_out() ? "daemon busy: " + no_reply + " (another client may be holding it)"
                                                  : "failed to send request to daemon",
                                DaemonUnreachable::Stage::NotSent, conn->timed_out(), timeout_seconds);
    }
    auto line = conn->read_line(kMaxResponseBytes);
    if (!line) {
        // The daemon reads a queued request once it is free, so a write may land after we give up.
        bool read_only = op == "get" || op == "list" || op == "getprefix";
        std::string why = conn->timed_out() ? "daemon busy: request sent but " + no_reply
                                            : "daemon closed the connection without a reply";
        if (!read_only) why += "; it may still be applied (check with list/get)";
        throw DaemonUnreachable(why, DaemonUnreachable::Stage::Sent, conn->timed_out(), timeout_seconds);
    }
    nlohmann::json resp;
    try {
        resp = nlohmann::json::parse(*line);
    } catch (const nlohmann::json::exception&) {
        wipe(*line);
        throw std::runtime_error("malformed response from daemon");
    }
    wipe(*line);
    return resp;
}

nlohmann::json DaemonClient::request_raw(const nlohmann::json& req) const {
    nlohmann::json resp = send(req);
    if (!resp.value("ok", false)) {
        throw std::runtime_error(resp.value("error", std::string("request failed")));
    }
    return resp;
}

namespace {

nlohmann::json make_request(const std::string& op, const std::string& key, std::optional<std::string_view> value) {
    nlohmann::json req{{"op", op}};
    if (!key.empty()) req["key"] = key;
    if (value) req["value"] = std::string(*value);
    return req;
}

}  // namespace

void DaemonClient::check_request(const std::string& op, const std::string& key,
                                 std::optional<std::string_view> value) const {
    nlohmann::json req = make_request(op, key, value);
    ScrubSecretFieldsOnExit scrub_req_on_exit(req);
    std::string request_line = serialize(req);
    wipe(request_line);
}

nlohmann::json DaemonClient::request(const std::string& op, const std::string& key,
                                     std::optional<std::string_view> value) const {
    nlohmann::json req = make_request(op, key, value);
    ScrubSecretFieldsOnExit scrub_req_on_exit(req);
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

// Confirms on a tty only: piped input has no typo to catch.
std::string read_new_passphrase(const std::string& prompt, const std::string& confirm_prompt) {
    std::string passphrase = read_passphrase(prompt);
    if (::isatty(STDIN_FILENO)) {
        std::string confirm = read_passphrase(confirm_prompt);
        bool matches = passphrase == confirm;
        wipe(confirm);
        if (!matches) throw std::runtime_error("passphrases do not match");
    }
    if (passphrase.size() < kRecommendedMinPassphraseChars) {
        std::cerr << "secretov: warning: new passphrase is shorter than "
                  << kRecommendedMinPassphraseChars << " characters\n";
    }
    return passphrase;
}

void export_env_var(const std::string& name, const std::string& value) {
    if (::setenv(name.c_str(), value.c_str(), 1) != 0) {
        throw std::runtime_error("setenv '" + name + "' failed");
    }
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
    std::optional<Manifest> manifest;
    BackendConfig backend() const { return manifest ? manifest->backend : BackendConfig{}; }
};

// (env, project) for a scope flag pair. -p names the project outright and the
// manifest is optional (only default_env needs it); otherwise the nearest
// manifest from cwd supplies the project.
ResolvedScope resolve_scope(const Paths& paths, const ScopeArgs& scope) {
    std::optional<Manifest> manifest;
    if (!scope.project || registry_project_root(paths.registry, *scope.project)) {
        manifest = resolve_manifest(paths, scope);
    }
    std::string project = scope.project ? *scope.project : manifest->project;
    std::string env = resolve_env(scope, manifest ? &*manifest : nullptr);
    return {std::move(env), std::move(project), std::move(manifest)};
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

// Parses `NAME [-p NAME] [-e ENV]`; prints the error and the usage and returns nullopt on a bad
// command line. A second positional would be an argv VALUE, which must never be accepted: it
// would leak the secret via /proc/<pid>/cmdline.
// raw_key (get/delete): NAME may start with '-' since any store key is a valid raw name, so
// only exactly -p/-e are flags and `--` ends the options; a missing NAME prints just the usage.
std::optional<std::string> parse_entry_args(const char* command, const char* usage, int argc, char** argv,
                                            ScopeArgs& scope, bool raw_key = false) {
    std::optional<std::string> name;
    bool options_ended = false;
    try {
        for (int i = 0; i < argc; ++i) {
            std::string arg = argv[i];
            if (!options_ended) {
                if (raw_key && arg == "--") {
                    options_ended = true;
                    continue;
                }
                bool is_flag = !raw_key || arg == "-p" || arg == "-e";
                if (is_flag && take_scope_arg(argc, argv, i, scope)) continue;
            }
            if (name || arg.empty() || (!raw_key && arg[0] == '-')) {
                throw std::runtime_error("unexpected argument '" + arg + "'");
            }
            name = arg;
        }
        if (!name) {
            if (raw_key) {
                std::cerr << usage;
                return std::nullopt;
            }
            throw std::runtime_error("missing KEY");
        }
    } catch (const std::exception& e) {
        std::cerr << "secretov " << command << ": " << e.what() << "\n" << usage;
        return std::nullopt;
    }
    return name;
}

// Where a get/set/delete NAME lives: the raw store key, or with -p/-e the scoped key
// on the backend the manifest names.
struct Target {
    std::unique_ptr<Backend> backend;
    std::string path;
};

Target resolve_target(const Paths& paths, const ScopeArgs& scope, const std::string& name) {
    if (!scope.project && !scope.env) return {open_backend(BackendConfig{}, paths), name};
    ResolvedScope resolved = resolve_scope(paths, scope);
    std::string path = scoped_key(resolved.env, resolved.project, name);
    return {open_backend(resolved.backend(), paths), std::move(path)};
}

}  // namespace

int cmd_init() {
    Paths paths = resolve_paths();
    try {
        std::string passphrase = read_new_passphrase("Passphrase: ", "Confirm passphrase: ");

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

int cmd_get(int argc, char** argv) {
    ScopeArgs scope;
    std::optional<std::string> name =
        parse_entry_args("get", "usage: secretov get KEY [-p NAME] [-e ENV]\n", argc, argv, scope, true);
    if (!name) return 2;
    Target target = resolve_target(resolve_paths(), scope, *name);
    Fetched fetched = target.backend->get_many({target.path});
    if (!fetched.failures.empty()) throw fetched.failures.begin()->second;
    std::string& value = fetched.values.at(target.path);
    std::cout << value << "\n";
    wipe(value);
    return 0;
}

int cmd_set(int argc, char** argv) {
    ScopeArgs scope;
    std::optional<std::string> name = parse_entry_args(
        "set", "usage: secretov set KEY [-p NAME] [-e ENV]   (value read from stdin)\n", argc, argv, scope);
    if (!name) return 2;
    Target target = resolve_target(resolve_paths(), scope, *name);
    // A tty gets a no-echo single-line prompt; a pipe is read whole (multi-line values).
    std::string value;
    if (::isatty(STDIN_FILENO)) {
        value = read_secret_line("Value for " + target.path + ": ");
        // A stray Enter would otherwise silently overwrite the key with "".
        if (value.empty()) {
            throw std::runtime_error(
                "empty value on the terminal; nothing stored (pipe an empty value if you mean it)");
        }
    } else {
        value = read_stdin_value();
    }
    target.backend->set(target.path, value);
    return 0;
}

int cmd_list(int argc, char** argv) {
    Paths paths = resolve_paths();
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
        if (resolved.manifest && resolved.manifest->backend.type != BackendType::Local) {
            // A cloud backend has no store to list: show what the manifest declares.
            for (const SecretEntry& e : entries_for(*resolved.manifest, resolved.env)) {
                std::cout << e.name << "\t" << (e.kind == EntryKind::Kv ? "kv" : "text") << "\t" << e.path << "\t"
                          << e.field << "\n";
            }
            return 0;
        }
        prefix = scope_prefix(resolved.env, resolved.project);
    }
    nlohmann::json resp = DaemonClient(paths).request("list");
    for (const auto& key : resp.value("keys", std::vector<std::string>{})) {
        if (key.compare(0, prefix.size(), prefix) == 0) std::cout << key << "\n";
    }
    return 0;
}

int cmd_delete(int argc, char** argv) {
    ScopeArgs scope;
    std::optional<std::string> name =
        parse_entry_args("delete", "usage: secretov delete KEY [-p NAME] [-e ENV]\n", argc, argv, scope, true);
    if (!name) return 2;
    Target target = resolve_target(resolve_paths(), scope, *name);
    target.backend->remove(target.path);
    return 0;
}

// ponytail: cmd_rotate/cmd_passwd leave passphrase copies (these strings, the
// request json and its dump()) unscrubbed on the heap; the process is
// non-dumpable and exits right after. Scrub them if clients become long-lived.
int cmd_rotate() {
    Paths paths = resolve_paths();
    std::string pass = read_passphrase("Current passphrase: ");
    DaemonClient(paths).request_raw(nlohmann::json{{"op", "rotate"}, {"old", pass}});
    std::cout << "rotated encryption key\n";
    return 0;
}

int cmd_passwd() {
    Paths paths = resolve_paths();
    std::string old_pass = read_passphrase("Current passphrase: ");
    std::string new_pass = read_new_passphrase("New passphrase: ", "Confirm new passphrase: ");
    DaemonClient(paths).request_raw(nlohmann::json{{"op", "passwd"}, {"old", old_pass}, {"new", new_pass}});
    std::cout << "passphrase changed\n";
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
        BackendConfig backend_config;
        std::vector<std::pair<std::string, std::string>> wanted;  // (envvar, path)
        KeyValues plain;                                          // (envvar, literal value)
        if (scope.project || scope.env || raw.empty()) {
            Manifest manifest = resolve_manifest(paths, scope);
            if (!raw.empty() && manifest.backend.type != BackendType::Local) {
                throw std::runtime_error(std::string("--secret names raw local-store keys; this manifest uses ") +
                                         backend_type_name(manifest.backend.type));
            }
            std::string env = resolve_env(scope, &manifest);
            for (const SecretEntry& e : entries_for(manifest, env)) {
                wanted.emplace_back(e.env_var, e.path);
            }
            plain = vars_for(manifest, env);
            backend_config = manifest.backend;
        }
        for (const auto& [key, envvar] : raw) wanted.emplace_back(envvar, key);

        if (dry_run) {
            // Manifest vars are plaintext in a committed file, so printing them
            // leaks nothing; secrets still show only their key.
            for (const auto& [envvar, value] : plain) std::cout << envvar << " = " << value << "\n";
            for (const auto& [envvar, path] : wanted) std::cout << envvar << " <- " << path << "\n";
            return 0;
        }

        // Fetch everything before touching our environment: nothing from a
        // manifest or a fetched value is applied to this process until every
        // request has been sent.
        std::unique_ptr<Backend> backend = open_backend(backend_config, paths);
        std::vector<std::string> paths_wanted;
        for (const auto& [envvar, path] : wanted) paths_wanted.push_back(path);
        Fetched fetched = backend->get_many(paths_wanted);
        std::vector<std::string> missing;
        for (const auto& [envvar, path] : wanted) {
            auto failure = fetched.failures.find(path);
            if (failure == fetched.failures.end()) continue;
            if (failure->second.kind != BackendError::Kind::NotFound) throw failure->second;
            missing.push_back(path);
        }
        if (!missing.empty()) throw std::runtime_error("missing secrets: " + join(missing, ", "));

        // Plaintext first, then manifest secrets, then --secret, so an explicit
        // --secret on the command line wins over a manifest var of the same name.
        std::vector<std::string> injected;
        auto inject = [&](const std::string& envvar, const std::string& value) {
            export_env_var(envvar, value);
            if (std::find(injected.begin(), injected.end(), envvar) == injected.end()) injected.push_back(envvar);
        };
        for (const auto& [envvar, value] : plain) inject(envvar, value);
        for (const auto& [envvar, path] : wanted) inject(envvar, fetched.values.at(path));
        for (auto& [path, value] : fetched.values) wipe(value);
        // Tells a secretov run inside the child which variables came from a manifest.
        if (!injected.empty()) {
            const char* inherited = std::getenv(kInjectedVar);
            export_env_var(kInjectedVar, (inherited && *inherited ? std::string(inherited) + "," : "") + join(injected, ","));
        }
    } catch (const std::exception& e) {
        std::cerr << "secretov exec: " << e.what() << "\n";
        return 1;
    }

    // Manifests cannot set PATH, so execvp searches the caller's own PATH.
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
        // A symlinked manifest is updated at its target (vetted by read_manifest_text), not replaced.
        std::string write_path = manifest_path;
        // symlink_status: a dangling link must fail in read_manifest_text, not be
        // replaced. It throws on any error other than "not found".
        if (std::filesystem::exists(std::filesystem::symlink_status(manifest_path))) {
            manifest_text = read_manifest_text(manifest_path);
            manifest = parse_manifest(manifest_text, manifest_path);
            if (scope.project && manifest->project != project) {
                throw std::runtime_error("manifest " + manifest_path + " names project '" + manifest->project +
                                         "', not '" + project + "'");
            }
            if (manifest->backend.type != BackendType::Local) {
                throw std::runtime_error(
                    "import is local-only for now; add entries to .secretov.yaml by hand, then 'secretov set ENTRY "
                    "-p NAME -e ENV'");
            }
            project = manifest->project;
            write_path = std::filesystem::canonical(manifest_path).string();
        }
        std::string env = resolve_env(scope, manifest ? &*manifest : nullptr);

        KeyValues pairs = parse_dotenv(read_file_string(file));
        if (pairs.empty()) throw std::runtime_error("nothing to import from " + file);

        DaemonClient client(paths);
        std::map<std::string, std::string> existing =
            client.request("getprefix", scope_prefix(env, project)).value("values", std::map<std::string, std::string>{});
        std::vector<std::string> collisions;
        KeyValues name_to_var;
        for (const auto& [var, value] : pairs) {
            std::string key = scoped_key(env, project, var);
            if (existing.count(key)) collisions.push_back(key);
            name_to_var.emplace_back(var, var);
        }
        if (!collisions.empty() && !overwrite) {
            throw std::runtime_error("already in store (pass --overwrite to replace):\n  " +
                                     join(collisions, "\n  "));
        }

        // A request send() would refuse (over the daemon's cap once escaped, or
        // invalid UTF-8) would fail midway through the sets below, leaving
        // earlier keys stored and no manifest.
        for (const auto& [var, value] : pairs) {
            try {
                client.check_request("set", scoped_key(env, project, var), value);
            } catch (const std::exception& e) {
                throw std::runtime_error(var + ": " + e.what() + "; nothing imported");
            }
        }

        // Prove the manifest edit before touching the store.
        std::string new_text = manifest_with_entries(manifest_text, project, env, name_to_var);
        // Storing first and then failing to write the manifest (or writing one
        // every later exec/import refuses) would orphan the secrets.
        if (new_text != manifest_text) require_creatable_manifest_dir(write_path);

        std::vector<std::string> stored;
        for (const auto& [var, value] : pairs) {
            std::string key = scoped_key(env, project, var);
            try {
                client.request("set", key, value);
            } catch (const std::exception& e) {
                throw std::runtime_error(var + ": " + e.what() +
                                         (stored.empty() ? ""
                                                         : "; manifest not updated; already stored (rerun with "
                                                           "--overwrite once fixed):\n  " + join(stored, "\n  ")));
            }
            stored.push_back(std::move(key));
        }
        if (new_text != manifest_text) write_file_atomic(write_path, new_text, 0644);

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
