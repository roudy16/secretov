#pragma once

// Project manifests (.secretov.yaml), the user registry (projects.yaml),
// dotenv parsing, and comment-preserving manifest edits. See DESIGN.md
// "Scopes". File names live in paths.hpp.

#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace secretov {

struct SecretEntry {
    std::string name;     // entry name under secrets:
    std::string key;      // full store key: env/project/name, or explicit `key:`
    std::string env_var;  // env_var_name
};

using KeyValues = std::vector<std::pair<std::string, std::string>>;

struct Manifest {
    std::string path;
    std::string project;
    std::optional<std::string> default_env;
    std::map<std::string, std::vector<SecretEntry>> envs;
    // Plaintext env vars per environment, in file order. These live in the
    // manifest itself and never touch the store — non-secret config only.
    std::map<std::string, KeyValues> vars;
};

// "env/project/name". Throws if any segment is empty or contains '/'.
std::string scoped_key(const std::string& env, const std::string& project, const std::string& name);
// "env/project/" — the getprefix argument for a scope.
std::string scope_prefix(const std::string& env, const std::string& project);

Manifest parse_manifest(const std::string& text, const std::string& path_for_errors);
Manifest load_manifest(const std::string& path);

// Nearest manifest walking up from start_dir; nullopt if none.
std::optional<std::string> find_manifest_upward(const std::string& start_dir);

// Project root from the registry, ${HOME}/${USER} expanded. nullopt when the
// registry file or the project entry is absent; throws on a malformed
// registry or a root that does not exist.
std::optional<std::string> registry_project_root(const std::string& registry_path,
                                                 const std::string& name);

// KEY=VALUE lines; comments, blanks, `export ` prefix, single/double quotes.
// Values are literal (no ${VAR} expansion). Throws on a malformed line.
KeyValues parse_dotenv(const std::string& text);

// Returns `text` with `NAME:\n  env_var_name: VAR` entries inserted under
// env.<env>.secrets, creating missing blocks and matching the file's
// indentation. Everything else (comments, spacing) is untouched. Entries
// already present are left alone. Empty text yields a fresh manifest for
// `project`. Throws if the result does not re-parse with the entries present.
std::string manifest_with_entries(const std::string& text, const std::string& project,
                                  const std::string& env, const KeyValues& name_to_var);

}  // namespace secretov
