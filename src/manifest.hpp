#pragma once

// Project manifests (.secretov.yaml), the user registry (projects.yaml),
// dotenv parsing, and comment-preserving manifest edits. See DESIGN.md
// "Scopes". File names live in paths.hpp.

#include <iostream>
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

// Rejects env names that load code into children (LD_*, BASH_ENV, ...; see
// manifest.cpp) in both vars and env_var_name.
Manifest parse_manifest(const std::string& text, const std::string& path_for_errors);

// The only way a manifest file is read. Throws unless the file is ours and not
// group/world-writable, and its directory (and a symlink target's directory)
// is ours or root's and not group/world-writable.
std::string read_manifest_text(const std::string& path);
// For a manifest about to be created: its directory passes read_manifest_text's
// directory check, is a directory, and we can write to it.
void require_creatable_manifest_dir(const std::string& manifest_path);
Manifest load_manifest(const std::string& path);

// Nearest manifest walking up from start_dir through directories we own;
// nullopt if none before the first directory owned by someone else. Does not
// vet the manifest itself (load_manifest does), so a bad one is never skipped.
std::optional<std::string> find_manifest_upward(const std::string& start_dir);

// Project root from the registry, ${HOME}/${USER} expanded. nullopt when the
// registry file or the project entry is absent; throws on a malformed
// registry or a root that does not exist.
std::optional<std::string> registry_project_root(const std::string& registry_path,
                                                 const std::string& name);

// KEY=VALUE lines; comments, blanks, `export ` prefix, single/double quotes.
// Values are literal (no ${VAR} expansion); double quotes decode \n \t \r \\ \".
// Throws on a malformed line, a duplicate key, or any other escape. An
// unquoted value loses a trailing " #..." comment, reported on `warnings`.
KeyValues parse_dotenv(const std::string& text, std::ostream& warnings = std::cerr);

// Returns `text` with `NAME:\n  env_var_name: VAR` entries inserted under
// env.<env>.secrets, creating missing blocks and matching the file's
// indentation. Everything else (comments, spacing) is untouched. Entries
// already present are left alone. Empty text yields a fresh manifest for
// `project`. Throws if the result does not re-parse with the entries present.
std::string manifest_with_entries(const std::string& text, const std::string& project,
                                  const std::string& env, const KeyValues& name_to_var);

}  // namespace secretov
