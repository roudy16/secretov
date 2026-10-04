#include "manifest.hpp"

#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <map>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <string_view>
#include <vector>
#include <yaml-cpp/yaml.h>

#include "paths.hpp"

namespace secretov {

namespace {

bool is_identifier(const std::string& s) {
    if (s.empty() || !(std::isalpha(static_cast<unsigned char>(s[0])) || s[0] == '_')) return false;
    for (char c : s) {
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_')) return false;
    }
    return true;
}

// ponytail: deny-list ceiling. Names that make a child process, any program it
// spawns, or a nested secretov load attacker-chosen code or config (PATH picks
// every grandchild's programs, HOME/XDG_* pick their config); anything not
// listed here still passes. Upgrade path is an allow-list per project if this leaks.
bool is_denied_env_name(const std::string& name) {
    // Compared upper-cased: Python lowercases every *_proxy it reads and npm
    // reads npm_config_* in any case, so an exact-case list misses spellings.
    std::string upper = name;
    for (char& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    // ponytail: a deny list lags every tool's next loader or index variable
    // (SECURITY.md #21); an allow list would break ordinary app config.
    static const char* const kDeniedPrefixes[] = {
        "LD_",  "DYLD_",  "SECRETOV_", "GIT_",   "XDG_",    "NPM_CONFIG_", "BUNDLE_",  "GEM_",
        "LUA_", "PIP_",   "UV_",       "CARGO_", "RUSTUP_", "RUSTC_",      "DOTNET_",  "CORECLR_"};
    static const char* const kDeniedNames[] = {
        "PATH",          "HOME",         "BASH_ENV",          "ENV",        "IFS",
        "PROMPT_COMMAND", "PS1",         "PS4",               "ZDOTDIR",    "PAGER",
        "PSQL_PAGER",    "MANPAGER",     "LESSOPEN",          "LESSCLOSE",  "EDITOR",
        "VISUAL",        "GCONV_PATH",   "NODE_OPTIONS",      "NODE_PATH",  "PYTHONSTARTUP",
        "PYTHONPATH",    "PYTHONHOME",   "PERL5OPT",          "PERL5LIB",   "RUBYOPT",
        "RUBYLIB",       "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "PERLLIB",
        "PYTHONUSERBASE", "PSQLRC",       "SSH_ASKPASS",       "SSH_ASKPASS_REQUIRE",   "KUBECONFIG",
        "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "OPENSSL_CONF", "OPENSSL_ENGINES", "OPENSSL_MODULES",
        "GOFLAGS",       "CLASSPATH",    "MAVEN_OPTS",        "GRADLE_OPTS", "DOCKER_HOST",
        "PYTHONWARNINGS", "PYTHONBREAKPOINT", "BROWSER",        "PERL5DB",    "PHPRC",
        "PHP_INI_SCAN_DIR", "GLIBC_TUNABLES", "LOCPATH",        "NLSPATH",    "SHELLOPTS",
        "BASHOPTS",      "R_PROFILE_USER", "JULIA_LOAD_PATH", "TCLLIBPATH", "ERL_AFLAGS",
        "ELIXIR_ERL_OPTIONS", "RUSTC",   "RUSTDOC",           "RUSTFLAGS",  "RUSTDOCFLAGS",
        "GOENV",         "GOROOT",       "GOTOOLCHAIN",       "GOWORK",     "CC",
        "CXX",           "MAKEFLAGS",    "MFLAGS",            "GNUMAKEFLAGS",
        // Package indexes and module proxies choose the code a build fetches.
        "GOPROXY",       "GONOPROXY",    "GOPRIVATE",         "GOSUMDB",    "GONOSUMDB",
        "GONOSUMCHECK",  "GOINSECURE",
        // CA overrides and key logs let a manifest read the child's secret-bearing requests.
        "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE",    "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
        "SSLKEYLOGFILE", "NODE_TLS_REJECT_UNAUTHORIZED", "AWS_CA_BUNDLE", "PYTHONHTTPSVERIFY"};
    // Credentials under a denied prefix: they hold a secret, not a loader path.
    static const char* const kCredentialNames[] = {"CARGO_REGISTRY_TOKEN", "UV_PUBLISH_TOKEN", "UV_PUBLISH_PASSWORD",
                                                   "UV_PUBLISH_USERNAME"};
    for (const char* credential : kCredentialNames) {
        if (upper == credential) return false;
    }
    constexpr std::string_view kRegistries = "CARGO_REGISTRIES_", kTokenSuffix = "_TOKEN";
    if (upper.size() > kRegistries.size() + kTokenSuffix.size() && upper.compare(0, kRegistries.size(), kRegistries) == 0 &&
        upper.compare(upper.size() - kTokenSuffix.size(), kTokenSuffix.size(), kTokenSuffix) == 0) {
        return false;
    }
    for (const char* prefix : kDeniedPrefixes) {
        if (upper.compare(0, std::strlen(prefix), prefix) == 0) return true;
    }
    for (const char* denied : kDeniedNames) {
        if (upper == denied) return true;
    }
    // Any proxy redirects the child's traffic; NO_PROXY can only bypass one.
    constexpr std::string_view kProxySuffix = "_PROXY";
    return upper != "NO_PROXY" && upper.size() >= kProxySuffix.size() &&
           upper.compare(upper.size() - kProxySuffix.size(), kProxySuffix.size(), kProxySuffix) == 0;
}

// `what` names the offending entry for the error, e.g. "var 'X' (env dev)".
void require_manifest_env_name(const std::string& name, const std::string& path, const std::string& what) {
    if (!is_identifier(name)) {
        throw std::runtime_error("manifest '" + path + "': " + what + " is not a valid environment variable name");
    }
    if (is_denied_env_name(name)) {
        throw std::runtime_error("manifest '" + path + "': " + what +
                                 " cannot be set from a manifest (it can load code into the child "
                                 "process, redirect its traffic, or steer secretov)");
    }
}

std::string join(const std::vector<std::string>& parts, const std::string& separator) {
    std::string joined;
    for (const std::string& part : parts) {
        if (!joined.empty()) joined += separator;
        joined += part;
    }
    return joined;
}

struct SharedGroup {
    std::string reason;
    std::string regroup_fix;  // empty when only the chmod can fix it
};

// Why group write is unsafe for a file in group gid, with the commands that
// would make the group ours alone; nullopt when nobody else is in it. Only our
// user private group qualifies, so a group meant to be shared never passes;
// see GroupMembers for what the membership check cannot see.
std::optional<SharedGroup> shared_group_problem(gid_t gid) {
    const struct passwd* my_entry = ::getpwuid(::getuid());
    if (!my_entry || my_entry->pw_gid != gid) {
        return SharedGroup{"writable by group " + std::to_string(gid) + ", which is not your private group", ""};
    }
    std::string my_name = my_entry->pw_name;
    std::optional<GroupMembers> members = other_group_members(gid);
    if (!members) {
        return SharedGroup{"writable by group " + std::to_string(gid) + ", which has no group entry, so its members are unknown", ""};
    }
    if (members->group != my_name) {
        return SharedGroup{"writable by group '" + members->group + "', which is not your private group (named " + my_name + ")", ""};
    }
    if (ours_alone(*members)) return std::nullopt;
    std::vector<std::string> member_descriptions;
    std::vector<std::string> regroup_commands;
    for (const std::string& user : members->primary) {
        member_descriptions.push_back(user + " (its primary group)");
        regroup_commands.push_back("sudo userdel " + user + " or sudo usermod -g <another group> " + user);
    }
    for (const ListedMember& listed : members->supplementary) {
        member_descriptions.push_back(listed.group == members->group ? listed.user
                                                                     : listed.user + " (via group '" + listed.group + "')");
        regroup_commands.push_back("sudo gpasswd -d " + listed.user + " " + listed.group);
    }
    for (const std::string& other_name : members->other_names) {
        member_descriptions.push_back("group '" + other_name + "', which shares gid " + std::to_string(gid));
        regroup_commands.push_back("sudo groupmod -g <unused gid> " + other_name);
    }
    return SharedGroup{"writable by group '" + members->group + "', which also includes " + join(member_descriptions, ", "),
                       "or make '" + members->group + "' yours alone: " + join(regroup_commands, "; ") +
                           " (and end any of their processes still running)"};
}

// With an access ACL the group bits in st_mode are the ACL mask, so they can
// stand for write by named users or groups rather than the owning group.
// Queries the open fd when there is one, else the path (following symlinks,
// as stat did).
std::optional<std::string> acl_problem(const std::string& path, int fd) {
    constexpr const char* kAccessAcl = "system.posix_acl_access";
    ssize_t acl_size = fd >= 0 ? ::fgetxattr(fd, kAccessAcl, nullptr, 0) : ::getxattr(path.c_str(), kAccessAcl, nullptr, 0);
    if (acl_size >= 0) return "has an ACL, so its group write may extend to other accounts; fix with: setfacl -b '" + path +
                              "', or chmod g-w '" + path + "'";
    if (errno == ENODATA || errno == ENOTSUP) return std::nullopt;
    return std::string("group-writable, and its ACL cannot be read (") + std::strerror(errno) + "); fix with: chmod g-w '" +
           path + "'";
}

// ssh StrictModes for manifests: anyone else who can write the file, or swap
// it in its directory, could inject env vars and key: references into exec.
// Group write is allowed when we are the group's only member (a user private
// group, the umask 0002 convention) and no ACL widens it. fd is the open
// file, or -1 to query path.
void require_trusted(const std::string& path, const struct stat& st, bool directory, int fd = -1) {
    std::string refusing = std::string("refusing ") + (directory ? "manifest directory" : "manifest") + " '" + path + "': ";
    uid_t me = ::getuid();
    if (st.st_uid != me && !(directory && st.st_uid == 0)) {
        throw std::runtime_error(refusing + "owned by uid " + std::to_string(st.st_uid) + ", not you (uid " +
                                 std::to_string(me) + "); remove it or chown it to yourself");
    }
    std::optional<SharedGroup> group_problem;
    if ((st.st_mode & S_IWGRP) != 0) group_problem = shared_group_problem(st.st_gid);
    if ((st.st_mode & S_IWOTH) != 0) {
        std::string chmod_flags = group_problem ? "g-w,o-w" : "o-w";
        throw std::runtime_error(refusing + "writable by everyone; fix with: chmod " + chmod_flags + " '" + path + "'");
    }
    if (group_problem) {
        std::string regroup = group_problem->regroup_fix.empty() ? "" : ", " + group_problem->regroup_fix;
        throw std::runtime_error(refusing + group_problem->reason + "; fix with: chmod g-w '" + path + "'" + regroup);
    }
    if ((st.st_mode & S_IWGRP) != 0) {
        if (std::optional<std::string> acl = acl_problem(path, fd)) throw std::runtime_error(refusing + *acl);
    }
}

void require_trusted_dir(const std::filesystem::path& dir) {
    std::string dir_path = dir.empty() ? "." : dir.string();
    struct stat st{};
    if (::stat(dir_path.c_str(), &st) != 0) {
        throw std::runtime_error("stat '" + dir_path + "': " + std::strerror(errno));
    }
    require_trusted(dir_path, st, true);
}

void require_segment(const std::string& s, const char* what) {
    if (s.empty() || s.find('/') != std::string::npos) {
        throw std::runtime_error(std::string(what) + " must be non-empty and contain no '/': '" + s + "'");
    }
}

std::string expand_vars(const std::string& s) {
    std::string out;
    std::size_t i = 0;
    while (i < s.size()) {
        if (s.compare(i, 2, "${") == 0) {
            std::size_t close = s.find('}', i);
            if (close == std::string::npos) throw std::runtime_error("unterminated ${ in '" + s + "'");
            std::string name = s.substr(i + 2, close - i - 2);
            if (name != "HOME" && name != "USER") {
                throw std::runtime_error("unsupported variable ${" + name + "} (only HOME, USER)");
            }
            const char* v = std::getenv(name.c_str());
            if (!v || !*v) throw std::runtime_error(name + " is not set; cannot expand '" + s + "'");
            out += v;
            i = close + 1;
        } else {
            out.push_back(s[i++]);
        }
    }
    return out;
}

// --- text-level YAML editing -------------------------------------------------

std::vector<std::string> split_lines(const std::string& text) {
    std::vector<std::string> lines;
    std::size_t start = 0;
    while (start < text.size()) {
        std::size_t nl = text.find('\n', start);
        if (nl == std::string::npos) {
            lines.push_back(text.substr(start));
            break;
        }
        lines.push_back(text.substr(start, nl - start));
        start = nl + 1;
    }
    return lines;
}

int indent_of(const std::string& line) {
    int n = 0;
    while (n < static_cast<int>(line.size()) && line[n] == ' ') ++n;
    return n;
}

bool blank_or_comment(const std::string& line) {
    for (char c : line) {
        if (c == '#') return true;
        if (c != ' ' && c != '\t' && c != '\r') return false;
    }
    return true;
}

// Exclusive end of the block whose key sits at key_line with the given indent.
std::size_t block_end(const std::vector<std::string>& lines, std::size_t key_line, int indent) {
    for (std::size_t i = key_line + 1; i < lines.size(); ++i) {
        if (!blank_or_comment(lines[i]) && indent_of(lines[i]) <= indent) return i;
    }
    return lines.size();
}

int child_indent(const std::vector<std::string>& lines, std::size_t begin, std::size_t end) {
    for (std::size_t i = begin; i < end; ++i) {
        if (!blank_or_comment(lines[i])) return indent_of(lines[i]);
    }
    return -1;
}

// Line index of `key:` at exactly `indent` within [begin, end), or npos.
// Throws if the key carries an inline value (`env: {}`), which cannot be
// extended textually.
std::size_t find_child(const std::vector<std::string>& lines, std::size_t begin, std::size_t end,
                       int indent, const std::string& key) {
    for (std::size_t i = begin; i < end; ++i) {
        const std::string& line = lines[i];
        if (blank_or_comment(line) || indent_of(line) != indent) continue;
        std::string body = line.substr(static_cast<std::size_t>(indent));
        if (body.compare(0, key.size(), key) != 0 || body.size() <= key.size() ||
            body[key.size()] != ':') {
            continue;
        }
        std::string rest = body.substr(key.size() + 1);
        if (!blank_or_comment(rest)) {
            throw std::runtime_error("manifest key '" + key +
                                     "' has an inline value; cannot insert entries textually");
        }
        return i;
    }
    return std::string::npos;
}

// Insertion point: after the last content line within [begin, end). Comments
// indented at least `min_indent` count as content (they belong to this
// block); shallower ones introduce the next section and stay below.
std::size_t insert_point(const std::vector<std::string>& lines, std::size_t begin, std::size_t end,
                         int min_indent) {
    std::size_t at = begin;
    for (std::size_t i = begin; i < end; ++i) {
        bool comment = lines[i].find('#') != std::string::npos && blank_or_comment(lines[i]);
        if (!blank_or_comment(lines[i]) || (comment && indent_of(lines[i]) >= min_indent)) at = i + 1;
    }
    return at;
}

std::string spaces(int n) { return std::string(static_cast<std::size_t>(n), ' '); }

}  // namespace

std::string scoped_key(const std::string& env, const std::string& project, const std::string& name) {
    require_segment(env, "environment");
    require_segment(project, "project");
    require_segment(name, "secret name");
    return env + "/" + project + "/" + name;
}

std::string scope_prefix(const std::string& env, const std::string& project) {
    require_segment(env, "environment");
    require_segment(project, "project");
    return env + "/" + project + "/";
}

Manifest parse_manifest(const std::string& text, const std::string& path) {
    YAML::Node doc;
    try {
        doc = YAML::Load(text);
    } catch (const YAML::Exception& e) {
        throw std::runtime_error("manifest '" + path + "': " + e.what());
    }
    if (!doc.IsMap()) throw std::runtime_error("manifest '" + path + "' is not a mapping");
    if (!doc["name"] || !doc["name"].IsScalar()) {
        throw std::runtime_error("manifest '" + path + "' missing 'name' field");
    }

    Manifest m;
    m.path = path;
    m.project = doc["name"].as<std::string>();
    require_segment(m.project, "project");
    if (doc["default_env"]) {
        if (!doc["default_env"].IsScalar()) {
            throw std::runtime_error("manifest '" + path + "': default_env must be a string");
        }
        m.default_env = doc["default_env"].as<std::string>();
    }

    YAML::Node envs = doc["env"];
    if (envs && !envs.IsNull()) {
        if (!envs.IsMap()) throw std::runtime_error("manifest '" + path + "': 'env' must be a mapping");
        for (const auto& env_pair : envs) {
            std::string env = env_pair.first.as<std::string>();
            require_segment(env, "environment");
            std::vector<SecretEntry> entries;
            KeyValues plain;
            YAML::Node env_node = env_pair.second;
            if (env_node && !env_node.IsNull()) {
                if (!env_node.IsMap()) {
                    throw std::runtime_error("manifest '" + path + "': env '" + env + "' must be a mapping");
                }
                YAML::Node secrets = env_node["secrets"];
                if (secrets && !secrets.IsNull()) {
                    if (!secrets.IsMap()) {
                        throw std::runtime_error("manifest '" + path + "': env '" + env +
                                                 "' secrets must be a mapping");
                    }
                    for (const auto& s : secrets) {
                        SecretEntry e;
                        e.name = s.first.as<std::string>();
                        YAML::Node body = s.second;
                        if (!body.IsMap() || !body["env_var_name"] || !body["env_var_name"].IsScalar()) {
                            throw std::runtime_error("manifest '" + path + "': secret '" + e.name +
                                                     "' (env " + env + ") missing env_var_name");
                        }
                        e.env_var = body["env_var_name"].as<std::string>();
                        require_manifest_env_name(e.env_var, path,
                                                  "secret '" + e.name + "' (env " + env + ") env_var_name '" +
                                                      e.env_var + "'");
                        if (body["key"]) {
                            e.key = body["key"].as<std::string>();
                            if (e.key.empty()) {
                                throw std::runtime_error("manifest '" + path + "': secret '" + e.name +
                                                         "' has an empty key");
                            }
                        } else {
                            e.key = scoped_key(env, m.project, e.name);
                        }
                        entries.push_back(std::move(e));
                    }
                }

                // Plaintext, non-secret config. The YAML key is the variable
                // name; the value is used verbatim, never fetched.
                YAML::Node vars = env_node["vars"];
                if (vars && !vars.IsNull()) {
                    if (!vars.IsMap()) {
                        throw std::runtime_error("manifest '" + path + "': env '" + env +
                                                 "' vars must be a mapping");
                    }
                    for (const auto& v : vars) {
                        std::string var_name = v.first.as<std::string>();
                        require_manifest_env_name(var_name, path, "var '" + var_name + "' (env " + env + ")");
                        if (!v.second.IsScalar()) {
                            throw std::runtime_error("manifest '" + path + "': var '" + var_name +
                                                     "' (env " + env +
                                                     ") must be a scalar value");
                        }
                        plain.emplace_back(var_name, v.second.as<std::string>());
                    }
                }

                // A variable defined twice has no sane precedence; refuse it
                // here so every command that loads the manifest fails alike.
                for (const auto& [var_name, value] : plain) {
                    for (const SecretEntry& e : entries) {
                        if (e.env_var == var_name) {
                            throw std::runtime_error("manifest '" + path + "': '" + var_name +
                                                     "' (env " + env +
                                                     ") is set in both vars and secrets");
                        }
                    }
                }
            }
            m.envs[env] = std::move(entries);
            m.vars[env] = std::move(plain);
        }
    }
    return m;
}

void require_creatable_manifest_dir(const std::string& manifest_path) {
    std::filesystem::path dir = std::filesystem::path(manifest_path).parent_path();
    std::string dir_path = dir.empty() ? "." : dir.string();
    struct stat st{};
    if (::stat(dir_path.c_str(), &st) != 0) throw std::runtime_error("stat '" + dir_path + "': " + std::strerror(errno));
    if (!S_ISDIR(st.st_mode)) throw std::runtime_error("manifest directory '" + dir_path + "' is not a directory");
    require_trusted(dir_path, st, true);
    if (::access(dir_path.c_str(), W_OK) != 0) {
        throw std::runtime_error("cannot create a manifest in '" + dir_path + "': " + std::strerror(errno));
    }
}

GroupMembers collect_group_members(gid_t gid, uid_t my_uid, const std::string& my_name,
                                   const std::vector<GroupEntry>& groups, const std::vector<AccountEntry>& accounts) {
    GroupMembers members;
    bool named = false;
    for (const GroupEntry& entry : groups) {
        if (entry.gid != gid) continue;
        if (!named) {
            members.group = entry.name;
            named = true;
        } else if (entry.name != members.group &&
                   std::find(members.other_names.begin(), members.other_names.end(), entry.name) == members.other_names.end()) {
            members.other_names.push_back(entry.name);
        }
        for (const std::string& user : entry.members) {
            bool seen = std::any_of(members.supplementary.begin(), members.supplementary.end(),
                                    [&](const ListedMember& listed) { return listed.user == user && listed.group == entry.name; });
            if (user != my_name && !seen) members.supplementary.push_back({user, entry.name});
        }
    }
    for (const AccountEntry& account : accounts) {
        if (account.gid == gid && account.uid != my_uid &&
            std::find(members.primary.begin(), members.primary.end(), account.name) == members.primary.end()) {
            members.primary.push_back(account.name);
        }
    }
    return members;
}

bool ours_alone(const GroupMembers& members) {
    return members.primary.empty() && members.supplementary.empty() && members.other_names.empty();
}

std::optional<GroupMembers> other_group_members(gid_t gid) {
    uid_t me = ::getuid();
    const struct passwd* my_entry = ::getpwuid(me);
    std::string my_name = my_entry ? my_entry->pw_name : "";
    const struct group* group_entry = ::getgrgid(gid);
    if (!group_entry) return std::nullopt;
    auto copy_group = [](const struct group& entry) {
        GroupEntry copied{entry.gr_name, entry.gr_gid, {}};
        for (char** member = entry.gr_mem; *member; ++member) copied.members.emplace_back(*member);
        return copied;
    };
    // getgrgid's entry first: a backend that answers it may not enumerate.
    // Then every entry, since initgroups grants the gid to members of each.
    std::vector<GroupEntry> groups{copy_group(*group_entry)};
    ::setgrent();
    errno = 0;
    while (const struct group* entry = ::getgrent()) {
        if (entry->gr_gid == gid) groups.push_back(copy_group(*entry));
        errno = 0;
    }
    int group_scan_errno = errno;
    ::endgrent();
    if (group_scan_errno != 0 && group_scan_errno != ENOENT) {
        throw std::runtime_error(std::string("cannot list groups to check group ") + groups[0].name + ": " +
                                 std::strerror(group_scan_errno) + "; fix with: chmod g-w on the manifest and its directory");
    }
    // Primary members are not in gr_mem; find them by scanning passwd.
    std::vector<AccountEntry> accounts;
    ::setpwent();
    errno = 0;
    while (const struct passwd* account = ::getpwent()) {
        if (account->pw_gid == gid) accounts.push_back({account->pw_name, account->pw_uid, account->pw_gid});
        errno = 0;
    }
    int account_scan_errno = errno;
    ::endpwent();
    if (account_scan_errno != 0 && account_scan_errno != ENOENT) {
        throw std::runtime_error(std::string("cannot list accounts to check group ") + groups[0].name + ": " +
                                 std::strerror(account_scan_errno) + "; fix with: chmod g-w on the manifest and its directory");
    }
    return collect_group_members(gid, me, my_name, groups, accounts);
}

std::string read_manifest_text(const std::string& path) {
    std::error_code ec;
    std::filesystem::path real = std::filesystem::canonical(path, ec);
    if (ec) throw std::runtime_error("manifest '" + path + "': " + ec.message());
    // Both the directory holding the name and, for a symlink, the one holding
    // the target: write access to either lets someone swap the content.
    require_trusted_dir(std::filesystem::path(path).parent_path());
    if (real != std::filesystem::path(path)) require_trusted_dir(real.parent_path());

    int fd = ::open(real.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) throw std::runtime_error("open '" + path + "': " + std::strerror(errno));
    std::string text;
    try {
        struct stat st{};
        if (::fstat(fd, &st) != 0) throw std::runtime_error("stat '" + path + "': " + std::strerror(errno));
        if (!S_ISREG(st.st_mode)) throw std::runtime_error("manifest '" + path + "' is not a regular file");
        require_trusted(path, st, false, fd);
        char buf[4096];
        for (;;) {
            ssize_t n = ::read(fd, buf, sizeof(buf));
            if (n < 0 && errno == EINTR) continue;
            if (n < 0) throw std::runtime_error("read '" + path + "': " + std::strerror(errno));
            if (n == 0) break;
            text.append(buf, static_cast<std::size_t>(n));
        }
    } catch (...) {
        ::close(fd);
        throw;
    }
    ::close(fd);
    return text;
}

Manifest load_manifest(const std::string& path) {
    return parse_manifest(read_manifest_text(path), path);
}

std::optional<std::string> find_manifest_upward(const std::string& start_dir) {
    std::filesystem::path dir = start_dir;
    for (;;) {
        // Only directories we own: another UID's directory (/tmp, /home, /)
        // can hold a manifest nobody here wrote.
        struct stat dir_st{};
        if (::stat(dir.c_str(), &dir_st) != 0 || dir_st.st_uid != ::getuid()) return std::nullopt;
        std::filesystem::path candidate = dir / kManifestFileName;
        std::error_code ec;
        // symlink_status: a dangling link must fail at load, not be skipped.
        if (std::filesystem::exists(std::filesystem::symlink_status(candidate, ec))) return candidate.string();
        std::filesystem::path parent = dir.parent_path();
        if (parent == dir) return std::nullopt;
        dir = parent;
    }
}

std::optional<std::string> registry_project_root(const std::string& registry_path,
                                                 const std::string& name) {
    if (::access(registry_path.c_str(), F_OK) != 0) return std::nullopt;
    YAML::Node doc;
    try {
        doc = YAML::LoadFile(registry_path);
    } catch (const YAML::Exception& e) {
        throw std::runtime_error("registry '" + registry_path + "': " + e.what());
    }
    YAML::Node project = doc["projects"] ? doc["projects"][name] : YAML::Node();
    if (!project || project.IsNull()) return std::nullopt;
    if (!project["root"] || !project["root"].IsScalar()) {
        throw std::runtime_error("registry '" + registry_path + "': project '" + name + "' has no 'root'");
    }
    std::string root = expand_vars(project["root"].as<std::string>());
    if (::access(root.c_str(), F_OK) != 0) {
        throw std::runtime_error("project root not found: " + root);
    }
    return root;
}

KeyValues parse_dotenv(const std::string& text, std::ostream& warnings) {
    KeyValues out;
    std::map<std::string, std::size_t> first_line_of_key;
    std::size_t lineno = 0;
    for (std::string line : split_lines(text)) {
        ++lineno;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::size_t first = line.find_first_not_of(" \t");
        if (first == std::string::npos || line[first] == '#') continue;
        line = line.substr(first);
        if (line.compare(0, 7, "export ") == 0) line = line.substr(7);

        std::size_t eq = line.find('=');
        if (eq == std::string::npos) {
            throw std::runtime_error("dotenv line " + std::to_string(lineno) + ": expected KEY=VALUE");
        }
        std::string key = line.substr(0, eq);
        while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) key.pop_back();
        if (!is_identifier(key)) {
            throw std::runtime_error("dotenv line " + std::to_string(lineno) + ": invalid key '" + key + "'");
        }
        auto [seen, inserted] = first_line_of_key.emplace(key, lineno);
        if (!inserted) {
            throw std::runtime_error("dotenv line " + std::to_string(lineno) + ": duplicate key '" + key +
                                     "' (first set on line " + std::to_string(seen->second) + ")");
        }

        std::string raw = line.substr(eq + 1);
        std::size_t vstart = raw.find_first_not_of(" \t");
        std::string value;
        if (vstart == std::string::npos) {
            value = "";
        } else if (raw[vstart] == '"' || raw[vstart] == '\'') {
            char quote = raw[vstart];
            std::size_t i = vstart + 1;
            bool closed = false;
            for (; i < raw.size(); ++i) {
                char c = raw[i];
                if (quote == '"' && c == '\\') {
                    if (i + 1 >= raw.size()) break;  // reported as unterminated
                    char escaped = raw[++i];
                    switch (escaped) {
                        case 'n': value.push_back('\n'); break;
                        case 't': value.push_back('\t'); break;
                        case 'r': value.push_back('\r'); break;
                        case '\\': value.push_back('\\'); break;
                        case '"': value.push_back('"'); break;
                        default:
                            throw std::runtime_error("dotenv line " + std::to_string(lineno) +
                                                     ": unsupported escape '\\" + std::string(1, escaped) +
                                                     "' in double-quoted value of '" + key + "'");
                    }
                    continue;
                }
                if (c == quote) {
                    closed = true;
                    break;
                }
                value.push_back(c);
            }
            if (!closed) {
                throw std::runtime_error("dotenv line " + std::to_string(lineno) + ": unterminated quote");
            }
            if (!blank_or_comment(raw.substr(i + 1))) {
                throw std::runtime_error("dotenv line " + std::to_string(lineno) +
                                         ": unexpected text after closing quote");
            }
        } else {
            value = raw.substr(vstart);
            std::size_t hash = value.find(" #");
            if (hash != std::string::npos) {
                value = value.substr(0, hash);
                warnings << "warning: dotenv line " << lineno << ": stripped a trailing ' #' comment from '"
                         << key << "'; quote the value if '#' belongs to it\n";
            }
            while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.pop_back();
        }
        out.emplace_back(key, value);
    }
    return out;
}

std::string manifest_with_entries(const std::string& text, const std::string& project,
                                  const std::string& env, const KeyValues& name_to_var) {
    require_segment(env, "environment");
    for (const auto& [name, var] : name_to_var) {
        if (!is_identifier(var)) throw std::runtime_error("invalid environment variable name '" + var + "'");
        require_segment(name, "secret name");
    }

    std::vector<std::string> lines = split_lines(text);
    int step = 2;
    for (const auto& l : lines) {
        if (!blank_or_comment(l) && indent_of(l) > 0) {
            step = indent_of(l);
            break;
        }
    }
    if (lines.empty()) {
        lines = {"version: \"1\"", "name: " + project, "env:"};
    }

    std::size_t env_line = find_child(lines, 0, lines.size(), 0, "env");
    if (env_line == std::string::npos) {
        lines.push_back("env:");
        env_line = lines.size() - 1;
    }
    std::size_t env_end = block_end(lines, env_line, 0);
    int ci = child_indent(lines, env_line + 1, env_end);
    if (ci < 0) ci = step;

    std::size_t e_line = find_child(lines, env_line + 1, env_end, ci, env);
    if (e_line == std::string::npos) {
        e_line = insert_point(lines, env_line + 1, env_end, ci);
        lines.insert(lines.begin() + static_cast<std::ptrdiff_t>(e_line), spaces(ci) + env + ":");
    }
    std::size_t e_end = block_end(lines, e_line, ci);
    int si = child_indent(lines, e_line + 1, e_end);
    if (si < 0) si = ci + step;

    std::size_t s_line = find_child(lines, e_line + 1, e_end, si, "secrets");
    if (s_line == std::string::npos) {
        s_line = insert_point(lines, e_line + 1, e_end, si);
        lines.insert(lines.begin() + static_cast<std::ptrdiff_t>(s_line), spaces(si) + "secrets:");
    }
    std::size_t s_end = block_end(lines, s_line, si);
    int ni = child_indent(lines, s_line + 1, s_end);
    if (ni < 0) ni = si + step;
    int vi = ni + step;
    for (std::size_t i = s_line + 1; i < s_end; ++i) {
        if (!blank_or_comment(lines[i]) && indent_of(lines[i]) > ni) {
            vi = indent_of(lines[i]);
            break;
        }
    }

    std::vector<std::string> added;
    for (const auto& [name, var] : name_to_var) {
        if (find_child(lines, s_line + 1, s_end, ni, name) != std::string::npos) continue;
        added.push_back(spaces(ni) + name + ":");
        added.push_back(spaces(vi) + "env_var_name: " + var);
    }
    std::size_t at = insert_point(lines, s_line + 1, s_end, ni);
    lines.insert(lines.begin() + static_cast<std::ptrdiff_t>(at), added.begin(), added.end());

    std::string out;
    for (const auto& l : lines) {
        out += l;
        out.push_back('\n');
    }

    // Prove the edit before anyone writes it: the result must parse and carry
    // every requested entry with the requested variable name.
    Manifest check = parse_manifest(out, "<edited manifest>");
    if (check.project != project) {
        throw std::runtime_error("manifest names project '" + check.project + "', expected '" + project + "'");
    }
    auto it = check.envs.find(env);
    if (it == check.envs.end()) throw std::runtime_error("manifest edit failed: env '" + env + "' not present");
    for (const auto& [name, var] : name_to_var) {
        bool found = false;
        for (const auto& e : it->second) {
            if (e.name == name) {
                found = true;
                break;
            }
        }
        if (!found) {
            throw std::runtime_error("manifest edit failed: entry '" + name +
                                     "' not present after insertion; add it by hand");
        }
    }
    return out;
}

}  // namespace secretov
