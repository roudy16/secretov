#include "manifest.hpp"

#include <unistd.h>

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
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
                        if (!is_identifier(e.env_var)) {
                            throw std::runtime_error("manifest '" + path + "': secret '" + e.name +
                                                     "' env_var_name '" + e.env_var +
                                                     "' is not a valid environment variable name");
                        }
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
                        if (!is_identifier(var_name)) {
                            throw std::runtime_error("manifest '" + path + "': var '" + var_name +
                                                     "' (env " + env +
                                                     ") is not a valid environment variable name");
                        }
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

Manifest load_manifest(const std::string& path) {
    return parse_manifest(read_file_string(path), path);
}

std::optional<std::string> find_manifest_upward(const std::string& start_dir) {
    std::string dir = start_dir;
    for (;;) {
        std::string candidate = (dir == "/" ? "" : dir) + "/" + kManifestFileName;
        if (::access(candidate.c_str(), F_OK) == 0) return candidate;
        if (dir == "/" || dir.empty()) return std::nullopt;
        std::size_t slash = dir.find_last_of('/');
        dir = slash == 0 ? "/" : dir.substr(0, slash);
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

KeyValues parse_dotenv(const std::string& text) {
    KeyValues out;
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
                if (quote == '"' && c == '\\' && i + 1 < raw.size()) {
                    char n = raw[++i];
                    value.push_back(n == 'n' ? '\n' : n);
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
            if (hash != std::string::npos) value = value.substr(0, hash);
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
