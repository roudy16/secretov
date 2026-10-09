#pragma once

// Project manifests (.secretov.yaml), the user registry (projects.yaml),
// dotenv parsing, and comment-preserving manifest edits. See DESIGN.md
// "Scopes". File names live in paths.hpp.

#include <sys/types.h>

#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace secretov {

enum class BackendType { Local, Aws, Gcp };
enum class EntryKind { Text, Kv };

struct BackendConfig {
    BackendType type = BackendType::Local;
    std::string location;  // aws: region, gcp: project; empty for local
};

const char* backend_type_name(BackendType type);  // "local", "aws", "gcp"

struct SecretEntry {
    std::string name;      // entry name under secrets:, a label
    EntryKind kind = EntryKind::Text;
    std::string path;      // local: full store key (env/project/name, or explicit `key:`);
                           // aws: secret name or ARN; gcp: secret id or full resource name
    std::string field;     // kv only: the JSON field (`key:`)
    std::string location;  // aws region / gcp project the path resolves in; empty for local
    std::string env_var;   // env_var_name
};

using KeyValues = std::vector<std::pair<std::string, std::string>>;

struct Manifest {
    std::string path;
    std::string project;
    BackendConfig backend;
    std::optional<std::string> default_env;
    std::map<std::string, std::vector<SecretEntry>> envs;
    // Plaintext env vars per environment, in file order. These live in the
    // manifest itself and never touch the store — non-secret config only.
    std::map<std::string, KeyValues> vars;
};

std::string join(const std::vector<std::string>& parts, const std::string& separator);

// "env/project/name". Throws if any segment is empty or contains '/'.
std::string scoped_key(const std::string& env, const std::string& project, const std::string& name);
// "env/project/" — the getprefix argument for a scope.
std::string scope_prefix(const std::string& env, const std::string& project);

// Rejects env names that load code into children (LD_*, BASH_ENV, ...; see
// manifest.cpp) in both vars and env_var_name, and unknown keys at every
// level. Cloud paths and locations are validated here, so a hostile manifest
// fails before any credential is loaded.
Manifest parse_manifest(const std::string& text, const std::string& path_for_errors);

// Everyone in group gid other than us, from the passwd and group databases:
// accounts whose primary group it is, members listed under any group entry
// with that gid, and the names of other entries sharing it. nullopt when gid
// has no group entry. Processes granted the gid outside these databases
// (systemd SupplementaryGroups=, setgid binaries, sessions of a removed
// member) and accounts a non-enumerating NSS backend hides are not seen.
struct ListedMember {
    std::string user;
    std::string group;
};
struct GroupMembers {
    std::string group;
    std::vector<std::string> primary;
    std::vector<ListedMember> supplementary;
    std::vector<std::string> other_names;
};
std::optional<GroupMembers> other_group_members(gid_t gid);

// The database-free core of other_group_members. groups holds every group
// entry seen, the one getgrgid returned first (it names the group);
// accounts holds every passwd entry seen. Duplicates are counted once.
struct GroupEntry {
    std::string name;
    gid_t gid;
    std::vector<std::string> members;
};
struct AccountEntry {
    std::string name;
    uid_t uid;
    gid_t gid;
};
GroupMembers collect_group_members(gid_t gid, uid_t my_uid, const std::string& my_name,
                                   const std::vector<GroupEntry>& groups, const std::vector<AccountEntry>& accounts);
// True when nobody but us is in the group: no other account, listed member,
// or group name sharing its gid.
bool ours_alone(const GroupMembers& members);

// The only way a manifest file is read. Throws unless the file is ours, and
// its directory (and a symlink target's directory) is ours or root's, and none
// is world-writable, or group-writable unless the group is our private group
// with nobody else in it and the inode has no access ACL. The error names the
// chmod, setfacl, or group change that fixes it. `noun` names the file kind
// in refusals ("registry" for projects.yaml).
std::string read_manifest_text(const std::string& path, const char* noun = "manifest");
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
// registry or a root that does not exist. The registry is trust-bearing and is
// read through read_manifest_text, so it needs the same owner/mode as a manifest.
std::optional<std::string> registry_project_root(const std::string& registry_path,
                                                 const std::string& name);

// The registry's `write_targets:` (aws-account:123456789012, gcp:project-id),
// each validated; empty when the registry or the list is absent.
std::vector<std::string> registry_write_targets(const std::string& registry_path);

// KEY=VALUE lines; comments, blanks, `export ` prefix, single/double quotes.
// Values are literal (no ${VAR} expansion); double quotes decode \n \t \r \\ \".
// Throws on a malformed line, a duplicate key, or any other escape. An
// unquoted value loses a trailing " #..." comment, reported on `warnings`.
KeyValues parse_dotenv(const std::string& text, std::ostream& warnings = std::cerr);

// Returns `text` with `NAME:\n  env_var_name: VAR` entries inserted under
// env.<env>.secrets, creating missing blocks and matching the file's
// indentation. Everything else (comments, spacing) is untouched. Entries
// already present are left alone, but must already have env_var_name VAR and
// path env/project/NAME. Empty text yields a fresh manifest for
// `project`. Throws if the result does not re-parse with the entries present.
std::string manifest_with_entries(const std::string& text, const std::string& project,
                                  const std::string& env, const KeyValues& name_to_var);

}  // namespace secretov
