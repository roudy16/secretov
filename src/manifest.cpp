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
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <vector>
#include <yaml-cpp/yaml.h>

#include "paths.hpp"

namespace secretov {

std::string join(const std::vector<std::string>& parts, const std::string& separator) {
    std::string joined;
    for (const std::string& part : parts) {
        if (!joined.empty()) joined += separator;
        joined += part;
    }
    return joined;
}

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
        "LUA_", "PIP_",   "UV_",       "CARGO_", "RUSTUP_", "RUSTC_",      "DOTNET_",  "CORECLR_",
        // Endpoint, proxy, CA or file valued; every gcloud property is a CLOUDSDK_* variable.
        "AWS_ENDPOINT_URL", "CLOUDSDK_"};
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
        "SSLKEYLOGFILE", "NODE_TLS_REJECT_UNAUTHORIZED", "AWS_CA_BUNDLE", "PYTHONHTTPSVERIFY",
        // Cloud endpoints and credential loading; AWS_PROFILE picks the account a nested secretov writes to.
        "AWS_EC2_METADATA_SERVICE_ENDPOINT", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_WEB_IDENTITY_TOKEN_FILE",
        "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_UNIVERSE_DOMAIN", "GCE_METADATA_HOST", "GCE_METADATA_IP",
        "AWS_PROFILE", "AWS_DEFAULT_PROFILE"};
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

std::runtime_error manifest_error(const std::string& path, const std::string& message) {
    return std::runtime_error("manifest '" + path + "': " + message);
}

// `what` names the offending entry for the error, e.g. "var 'X' (env dev)".
void require_manifest_env_name(const std::string& name, const std::string& path, const std::string& what) {
    if (!is_identifier(name)) throw manifest_error(path, what + " is not a valid environment variable name");
    if (is_denied_env_name(name)) {
        throw manifest_error(path, what +
                                       " cannot be set from a manifest (it can load code into the child "
                                       "process, redirect its traffic, or steer secretov)");
    }
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

std::string require_trusted_dir(const std::filesystem::path& dir) {
    std::string dir_path = dir.empty() ? "." : dir.string();
    struct stat st{};
    if (::stat(dir_path.c_str(), &st) != 0) {
        throw std::runtime_error("stat '" + dir_path + "': " + std::strerror(errno));
    }
    if (!S_ISDIR(st.st_mode)) throw std::runtime_error("manifest directory '" + dir_path + "' is not a directory");
    require_trusted(dir_path, st, true);
    return dir_path;
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
    std::istringstream stream(text);
    for (std::string line; std::getline(stream, line);) lines.push_back(line);
    return lines;
}

int indent_of(const std::string& line) {
    return static_cast<int>(std::min(line.find_first_not_of(' '), line.size()));
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

struct Block {
    std::size_t key_line;
    std::size_t end;   // exclusive
    int entry_indent;  // of the block's children
};

// The `key:` block at `indent` within [begin, end), inserted after the range's
// last content line when missing.
Block ensure_block(std::vector<std::string>& lines, std::size_t begin, std::size_t end, int indent, int step,
                   const std::string& key) {
    std::size_t key_line = find_child(lines, begin, end, indent, key);
    if (key_line == std::string::npos) {
        key_line = insert_point(lines, begin, end, indent);
        lines.insert(lines.begin() + static_cast<std::ptrdiff_t>(key_line), spaces(indent) + key + ":");
    }
    std::size_t block_end_line = block_end(lines, key_line, indent);
    int entry_indent = child_indent(lines, key_line + 1, block_end_line);
    return {key_line, block_end_line, entry_indent < 0 ? indent + step : entry_indent};
}

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

const char* backend_type_name(BackendType type) {
    switch (type) {
        case BackendType::Local: return "local";
        case BackendType::Aws: return "aws";
        case BackendType::Gcp: return "gcp";
    }
    return "";
}

namespace {

bool is_ascii_alnum(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }

bool is_lower_or_digit(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z'); }

// Alphanumerics plus `extra`, 1..max characters.
bool is_name(std::string_view s, std::string_view extra, std::size_t max) {
    return !s.empty() && s.size() <= max &&
           std::all_of(s.begin(), s.end(), [&](char c) { return is_ascii_alnum(c) || extra.find(c) != std::string_view::npos; });
}

bool is_aws_secret_name(std::string_view s) { return is_name(s, "/_+=.@-", 512); }

bool is_gcp_secret_id(std::string_view s) { return is_name(s, "_-", 255); }

// Lowercase id form only: project numbers and domain-scoped ids are refused so a pin compares one form.
bool is_gcp_project(std::string_view s) {
    return s.size() >= 6 && s.size() <= 30 && s.front() >= 'a' && s.front() <= 'z' && is_lower_or_digit(s.back()) &&
           std::all_of(s.begin(), s.end(), [](char c) { return is_lower_or_digit(c) || c == '-'; });
}

bool is_aws_account(std::string_view s) {
    return s.size() == 12 && std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; });
}

// ponytail: the `aws` partition's regions as of this build; a newer region is refused with an upgrade hint.
bool is_known_aws_region(const std::string& region) {
    static const char* const kRegions[] = {
        "us-east-1",      "us-east-2",      "us-west-1",      "us-west-2",      "af-south-1",     "ap-east-1",
        "ap-east-2",      "ap-south-1",     "ap-south-2",     "ap-southeast-1", "ap-southeast-2", "ap-southeast-3",
        "ap-southeast-4", "ap-southeast-5", "ap-southeast-6", "ap-southeast-7", "ap-northeast-1", "ap-northeast-2",
        "ap-northeast-3", "ca-central-1",   "ca-west-1",      "eu-central-1",   "eu-central-2",   "eu-west-1",
        "eu-west-2",      "eu-west-3",      "eu-north-1",     "eu-south-1",     "eu-south-2",     "il-central-1",
        "me-south-1",     "me-central-1",   "mx-central-1",   "sa-east-1"};
    return std::find(std::begin(kRegions), std::end(kRegions), region) != std::end(kRegions);
}

std::vector<std::string> split_on(const std::string& s, char separator) {
    std::vector<std::string> parts;
    std::size_t begin = 0;
    for (std::size_t at; (at = s.find(separator, begin)) != std::string::npos; begin = at + 1) {
        parts.push_back(s.substr(begin, at - begin));
    }
    parts.push_back(s.substr(begin));
    return parts;
}

void require_aws_region(const std::string& region, const std::string& manifest_path, const std::string& what) {
    if (!is_known_aws_region(region)) {
        throw manifest_error(manifest_path, what + " region '" + region + "' is not in this build's region table; upgrade secretov");
    }
}

void require_gcp_project(const std::string& project, const std::string& manifest_path, const std::string& what) {
    if (!is_gcp_project(project)) {
        throw manifest_error(manifest_path, what + " project '" + project + "' is not a valid GCP project id (lowercase id, 6-30 characters)");
    }
}

void refuse_unknown_keys(const YAML::Node& map, std::initializer_list<std::string_view> allowed, const std::string& path,
                         const std::string& where) {
    for (const auto& pair : map) {
        std::string key = pair.first.as<std::string>();
        if (std::find(allowed.begin(), allowed.end(), key) == allowed.end()) {
            throw manifest_error(path, "unknown key '" + key + "' in " + where);
        }
    }
}

// The `region:` (aws) or `project:` (gcp) in a backend or env mapping. The
// other key, or either on a local manifest, is refused. nullopt when absent.
std::optional<std::string> parse_location(const YAML::Node& node, BackendType type, const std::string& path,
                                          const std::string& where) {
    const std::string_view own_key = type == BackendType::Aws ? "region" : type == BackendType::Gcp ? "project" : "";
    for (const char* key : {"region", "project"}) {
        if (node[key] && key != own_key) {
            throw manifest_error(path, where + " '" + key + "' is not valid with backend type " + backend_type_name(type));
        }
    }
    if (own_key.empty() || !node[std::string(own_key)]) return std::nullopt;
    YAML::Node value_node = node[std::string(own_key)];
    if (!value_node.IsScalar()) throw manifest_error(path, where + " " + std::string(own_key) + " must be a string");
    std::string value = value_node.as<std::string>();
    if (type == BackendType::Aws) {
        require_aws_region(value, path, where);
    } else {
        require_gcp_project(value, path, where);
    }
    return value;
}

BackendConfig parse_backend(const YAML::Node& node, const std::string& path) {
    BackendConfig backend;
    if (!node) return backend;
    if (!node.IsMap()) throw manifest_error(path, "'backend' must be a mapping");
    refuse_unknown_keys(node, {"type", "region", "project"}, path, "backend:");
    if (!node["type"] || !node["type"].IsScalar()) throw manifest_error(path, "backend needs a type: local, aws or gcp");
    std::string type_name = node["type"].as<std::string>();
    if (type_name == "local") {
        backend.type = BackendType::Local;
    } else if (type_name == "aws") {
        backend.type = BackendType::Aws;
    } else if (type_name == "gcp") {
        backend.type = BackendType::Gcp;
    } else {
        throw manifest_error(path, "backend type '" + type_name + "' is not one of local, aws, gcp");
    }
    std::optional<std::string> location = parse_location(node, backend.type, path, "backend");
    if (backend.type != BackendType::Local) {
        if (!location) {
            throw manifest_error(path, std::string("backend type ") + backend_type_name(backend.type) + " needs " +
                                           (backend.type == BackendType::Aws ? "region" : "project"));
        }
        backend.location = *location;
    }
    return backend;
}

// Returns the location the path resolves in: the region of an ARN, else the env's.
std::string resolve_aws_path(const std::string& secret_path, const std::string& env_location, const std::string& manifest_path,
                             const std::string& described) {
    if (secret_path.compare(0, 4, "arn:") != 0) {
        if (!is_aws_secret_name(secret_path)) {
            throw manifest_error(manifest_path, described + " path is not a valid AWS secret name or ARN");
        }
        return env_location;
    }
    std::vector<std::string> parts = split_on(secret_path, ':');
    if (parts.size() != 7 || parts[1] != "aws" || parts[2] != "secretsmanager" || !is_aws_account(parts[4]) ||
        parts[5] != "secret" || !is_aws_secret_name(parts[6])) {
        throw manifest_error(manifest_path,
                             described + " path is not a valid ARN (arn:aws:secretsmanager:REGION:ACCOUNT:secret:NAME; partition aws only)");
    }
    require_aws_region(parts[3], manifest_path, described + " ARN");
    return parts[3];
}

// Returns the location the path resolves in: the project of a resource name, else the env's.
std::string resolve_gcp_path(const std::string& secret_path, const std::string& env_location, const std::string& manifest_path,
                             const std::string& described) {
    if (secret_path.compare(0, 9, "projects/") != 0) {
        if (!is_gcp_secret_id(secret_path)) {
            throw manifest_error(manifest_path, described + " path is not a valid GCP secret id or resource name");
        }
        return env_location;
    }
    std::vector<std::string> parts = split_on(secret_path, '/');
    if (parts.size() != 4 || parts[2] != "secrets" || !is_gcp_project(parts[1]) || !is_gcp_secret_id(parts[3])) {
        throw manifest_error(manifest_path, described + " path is not a valid resource name (projects/PROJECT/secrets/ID)");
    }
    return parts[1];
}

std::optional<std::string> optional_scalar(const YAML::Node& body, const char* key, const std::string& manifest_path,
                                           const std::string& described) {
    if (!body[key]) return std::nullopt;
    if (!body[key].IsScalar()) throw manifest_error(manifest_path, described + " " + key + " must be a string");
    std::string value = body[key].as<std::string>();
    if (value.empty()) throw manifest_error(manifest_path, described + " has an empty " + key);
    return value;
}

std::vector<SecretEntry> parse_env_secrets(YAML::Node secrets, const std::string& path, const std::string& env,
                                           const std::string& project, BackendType backend_type,
                                           const std::string& env_location) {
    std::vector<SecretEntry> entries;
    if (!secrets || secrets.IsNull()) return entries;
    if (!secrets.IsMap()) throw manifest_error(path, "env '" + env + "' secrets must be a mapping");
    for (const auto& secret_pair : secrets) {
        SecretEntry entry;
        entry.name = secret_pair.first.as<std::string>();
        std::string described = "secret '" + entry.name + "' (env " + env + ")";
        YAML::Node body = secret_pair.second;
        if (!body.IsMap() || !body["env_var_name"] || !body["env_var_name"].IsScalar()) {
            throw manifest_error(path, described + " missing env_var_name");
        }
        refuse_unknown_keys(body, {"env_var_name", "key", "kind", "path"}, path, described);
        entry.env_var = body["env_var_name"].as<std::string>();
        require_manifest_env_name(entry.env_var, path, described + " env_var_name '" + entry.env_var + "'");
        if (std::optional<std::string> kind = optional_scalar(body, "kind", path, described)) {
            if (*kind == "kv") {
                entry.kind = EntryKind::Kv;
            } else if (*kind != "text") {
                throw manifest_error(path, described + " kind must be text or kv");
            }
        }
        std::optional<std::string> key = optional_scalar(body, "key", path, described);
        std::optional<std::string> secret_path = optional_scalar(body, "path", path, described);
        if (backend_type == BackendType::Local) {
            if (secret_path) throw manifest_error(path, described + " path is for cloud backends; a local entry uses key:");
            if (entry.kind == EntryKind::Kv) throw manifest_error(path, described + " kind kv needs a cloud backend; local entries are text");
            entry.path = key ? *key : scoped_key(env, project, entry.name);
        } else {
            if (!secret_path) throw manifest_error(path, described + " needs an explicit path");
            if (entry.kind == EntryKind::Text && key) throw manifest_error(path, described + " key names a JSON field and needs kind: kv");
            if (entry.kind == EntryKind::Kv) {
                if (!key) throw manifest_error(path, described + " kind kv needs key");
                entry.field = *key;
            }
            entry.path = *secret_path;
            entry.location = backend_type == BackendType::Aws ? resolve_aws_path(entry.path, env_location, path, described)
                                                              : resolve_gcp_path(entry.path, env_location, path, described);
        }
        entries.push_back(std::move(entry));
    }
    return entries;
}

// Plaintext, non-secret config. The YAML key is the variable name; the value
// is used verbatim, never fetched.
KeyValues parse_env_vars(YAML::Node vars, const std::string& path, const std::string& env) {
    KeyValues plain;
    if (!vars || vars.IsNull()) return plain;
    if (!vars.IsMap()) throw manifest_error(path, "env '" + env + "' vars must be a mapping");
    for (const auto& var_pair : vars) {
        std::string var_name = var_pair.first.as<std::string>();
        require_manifest_env_name(var_name, path, "var '" + var_name + "' (env " + env + ")");
        if (!var_pair.second.IsScalar()) {
            throw manifest_error(path, "var '" + var_name + "' (env " + env + ") must be a scalar value");
        }
        plain.emplace_back(var_name, var_pair.second.as<std::string>());
    }
    return plain;
}

}  // namespace

Manifest parse_manifest(const std::string& text, const std::string& path) {
    // yaml-cpp throws from node access too (a non-scalar key, a map read as a
    // string), so the whole walk is covered to keep the manifest path.
    try {
        YAML::Node doc = YAML::Load(text);
        if (!doc.IsMap()) throw std::runtime_error("manifest '" + path + "' is not a mapping");
        refuse_unknown_keys(doc, {"version", "name", "backend", "default_env", "env"}, path, kManifestFileName);
        if (!doc["name"] || !doc["name"].IsScalar()) {
            throw std::runtime_error("manifest '" + path + "' missing 'name' field");
        }

        Manifest m;
        m.path = path;
        m.project = doc["name"].as<std::string>();
        require_segment(m.project, "project");
        m.backend = parse_backend(doc["backend"], path);
        if (doc["default_env"]) {
            if (!doc["default_env"].IsScalar()) throw manifest_error(path, "default_env must be a string");
            m.default_env = doc["default_env"].as<std::string>();
        }

        YAML::Node envs = doc["env"];
        if (!envs || envs.IsNull()) return m;
        if (!envs.IsMap()) throw manifest_error(path, "'env' must be a mapping");
        for (const auto& env_pair : envs) {
            std::string env = env_pair.first.as<std::string>();
            require_segment(env, "environment");
            std::vector<SecretEntry> entries;
            KeyValues plain;
            YAML::Node env_node = env_pair.second;
            if (env_node && !env_node.IsNull()) {
                if (!env_node.IsMap()) throw manifest_error(path, "env '" + env + "' must be a mapping");
                refuse_unknown_keys(env_node, {"vars", "secrets", "region", "project"}, path, "env '" + env + "'");
                std::string env_location =
                    parse_location(env_node, m.backend.type, path, "env '" + env + "'").value_or(m.backend.location);
                entries = parse_env_secrets(env_node["secrets"], path, env, m.project, m.backend.type, env_location);
                plain = parse_env_vars(env_node["vars"], path, env);
                // A variable defined twice has no sane precedence; refuse it
                // here so every command that loads the manifest fails alike.
                for (const auto& [var_name, value] : plain) {
                    for (const SecretEntry& entry : entries) {
                        if (entry.env_var == var_name) {
                            throw manifest_error(path, "'" + var_name + "' (env " + env + ") is set in both vars and secrets");
                        }
                    }
                }
            }
            m.envs[env] = std::move(entries);
            m.vars[env] = std::move(plain);
        }
        return m;
    } catch (const YAML::Exception& e) {
        throw manifest_error(path, e.what());
    }
}

void require_creatable_manifest_dir(const std::string& manifest_path) {
    std::string dir_path = require_trusted_dir(std::filesystem::path(manifest_path).parent_path());
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

namespace {

// Null node when the file is absent. Read through read_manifest_text: the
// registry holds write_targets, so it needs the manifests' owner/mode check.
YAML::Node load_registry(const std::string& registry_path) {
    if (::access(registry_path.c_str(), F_OK) != 0) return YAML::Node();
    std::string text = read_manifest_text(registry_path);
    try {
        return YAML::Load(text);
    } catch (const YAML::Exception& e) {
        throw std::runtime_error("registry '" + registry_path + "': " + e.what());
    }
}

}  // namespace

std::optional<std::string> registry_project_root(const std::string& registry_path,
                                                 const std::string& name) {
    YAML::Node doc = load_registry(registry_path);
    std::string root_spec;
    try {
        YAML::Node projects = doc["projects"];
        if (!projects || projects.IsNull()) return std::nullopt;
        // A non-const lookup would quietly turn a sequence into a map.
        if (!projects.IsMap()) throw std::runtime_error("registry '" + registry_path + "': 'projects' must be a mapping");
        YAML::Node project = projects[name];
        if (!project || project.IsNull()) return std::nullopt;
        if (!project.IsMap() || !project["root"] || !project["root"].IsScalar()) {
            throw std::runtime_error("registry '" + registry_path + "': project '" + name + "' has no 'root'");
        }
        root_spec = project["root"].as<std::string>();
    } catch (const YAML::Exception& e) {
        throw std::runtime_error("registry '" + registry_path + "': " + e.what());
    }
    std::string root = expand_vars(root_spec);
    if (::access(root.c_str(), F_OK) != 0) {
        throw std::runtime_error("project root not found: " + root);
    }
    return root;
}

std::vector<std::string> registry_write_targets(const std::string& registry_path) {
    YAML::Node doc = load_registry(registry_path);
    std::vector<std::string> targets;
    try {
        YAML::Node listed = doc["write_targets"];
        if (!listed || listed.IsNull()) return targets;
        if (!listed.IsSequence()) throw std::runtime_error("registry '" + registry_path + "': 'write_targets' must be a list");
        for (const YAML::Node& item : listed) {
            std::string target = item.IsScalar() ? item.as<std::string>() : "";
            bool aws_account = target.compare(0, 12, "aws-account:") == 0 && is_aws_account(target.substr(12));
            bool gcp_project = target.compare(0, 4, "gcp:") == 0 && is_gcp_project(target.substr(4));
            if (!aws_account && !gcp_project) {
                throw std::runtime_error("registry '" + registry_path + "': write_targets entry '" + target +
                                         "' must be aws-account:<12-digit account> or gcp:<project id>");
            }
            targets.push_back(std::move(target));
        }
    } catch (const YAML::Exception& e) {
        throw std::runtime_error("registry '" + registry_path + "': " + e.what());
    }
    return targets;
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
        if (vstart == std::string::npos) {
            out.emplace_back(key, "");
            continue;
        }
        std::string value;
        if (raw[vstart] == '"' || raw[vstart] == '\'') {
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
    for (const std::string& line : lines) {
        if (!blank_or_comment(line) && indent_of(line) > 0) {
            step = indent_of(line);
            break;
        }
    }
    if (lines.empty()) {
        lines = {"version: \"1\"", "name: " + project, "env:"};
    }

    Block env_root = ensure_block(lines, 0, lines.size(), 0, step, "env");
    Block env_block = ensure_block(lines, env_root.key_line + 1, env_root.end, env_root.entry_indent, step, env);
    Block secrets_block =
        ensure_block(lines, env_block.key_line + 1, env_block.end, env_block.entry_indent, step, "secrets");
    int name_indent = secrets_block.entry_indent;
    int value_indent = name_indent + step;
    for (std::size_t i = secrets_block.key_line + 1; i < secrets_block.end; ++i) {
        if (!blank_or_comment(lines[i]) && indent_of(lines[i]) > name_indent) {
            value_indent = indent_of(lines[i]);
            break;
        }
    }

    std::vector<std::string> added;
    for (const auto& [name, var] : name_to_var) {
        if (find_child(lines, secrets_block.key_line + 1, secrets_block.end, name_indent, name) != std::string::npos) {
            continue;
        }
        added.push_back(spaces(name_indent) + name + ":");
        added.push_back(spaces(value_indent) + "env_var_name: " + var);
    }
    std::size_t at = insert_point(lines, secrets_block.key_line + 1, secrets_block.end, name_indent);
    lines.insert(lines.begin() + static_cast<std::ptrdiff_t>(at), added.begin(), added.end());

    std::string out;
    for (const std::string& line : lines) {
        out += line;
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
        auto entry = std::find_if(it->second.begin(), it->second.end(),
                                  [&](const SecretEntry& candidate) { return candidate.name == name; });
        if (entry == it->second.end()) {
            throw std::runtime_error("manifest edit failed: entry '" + name +
                                     "' not present after insertion; add it by hand");
        }
        if (entry->env_var != var || entry->path != scoped_key(env, project, name)) {
            throw std::runtime_error("manifest entry '" + name + "' in env '" + env +
                                     "' already exists with a different key or env_var_name; fix it by hand");
        }
    }
    return out;
}

}  // namespace secretov
