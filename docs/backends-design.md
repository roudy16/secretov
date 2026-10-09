# secretov — pluggable backends

Status: approved design, 2026-10-09; Phase 1 (seam) built, Phases 2-5 not.
It amends DESIGN.md as listed under "Security deltas"; the Phase 1 amendments
are in DESIGN.md (Backends). Owner rulings are in the Decisions log at the end.

## Goal and non-goals

Split secretov into a **manifest front end** (resolution, trust checks,
`exec`, `import`, TUI) and a **secrets backend** chosen by the manifest: the
built-in local daemon, AWS Secrets Manager or GCP Secret Manager. A manifest
stays names-only and safe to commit, whichever backend it names.

- One `secretov` binary; the manifest's `backend:` block picks the backend.
  One backend per manifest, no mixing.
- secretov never runs an auth flow or a provider CLI. Backends use
  credentials already on the machine: env vars and credential files.
- A manifest can never change *where* secretov sends a request (Security
  deltas).
- Two personas, no role config: a developer reads (`exec`, `get -p/-e`), an
  administrator also writes (`set`, `delete -p/-e`, TUI edits); the role is
  whatever provider IAM allows. `get`/`delete -p/-e` are **new flags**.
- Cloud backends are compile-time opt-in. With both off, the build and its
  dependency set are exactly today's.

Non-goals (for now): mixing backends, cross-backend migration, `import` into
cloud backends, adding cloud entries from the TUI, plugin backends, endpoint
overrides (LocalStack, FIPS), GCP regional secrets, the `aws-cn` and
`aws-us-gov` partitions, binary secrets, caching, CI against real clouds.

## Manifest syntax

```yaml
version: "1"
name: flows-admin
backend:                 # absent => local daemon
  type: aws              # local | aws | gcp
  region: us-east-1      # aws: required; gcp uses project: instead
default_env: dev
env:
  dev:
    vars: { LOG_LEVEL: debug }
    secrets:
      # text: the whole provider secret is the value
      database-url: { kind: text, path: dev/flows-admin/database-url, env_var_name: DATABASE_URL }
      # kv: one field of a JSON-object secret; entries sharing a path cost one fetch
      db-user:      { kind: kv, path: dev/flows-admin/db, key: username, env_var_name: DB_USER }
      db-password:  { kind: kv, path: dev/flows-admin/db, key: password, env_var_name: DB_PASSWORD }
      # full ARN: another account and region
      stripe-key:
        path: arn:aws:secretsmanager:eu-west-1:123456789012:secret:shared/stripe-AbCdEf
        env_var_name: STRIPE_KEY
  prod:
    region: eu-west-1                     # per-env default for name paths
    secrets: { ... }
```

GCP is the same shape with `backend: { type: gcp, project: acme-secrets }`,
per-env `project:`, bare ids (`path: dev-db`) or full resource names
(`path: projects/acme-shared/secrets/stripe-key`).

Rules:

- **Shared facts in the manifest, machine facts out.** Profile, account and
  credential file come from the caller's environment only. AWS needs
  `backend.region` (AWS has no default); GCP needs `backend.project` (no ADC
  or gcloud discovery, which differs per machine). An env may set `region:`
  (aws) or `project:` (gcp) as its default for unqualified paths; the other
  key, or either on a local manifest, is a parse error, in an env and in
  `backend:` alike (`backend.project` with `type: aws` is refused).
- **No `endpoint:` field.** Hosts are fixed.
- **Unknown keys are refused** at top level, in `backend:`, in an env and in
  a secret entry, for every manifest. Today's parser ignores them, which is
  exactly how an old binary reads `backend: aws` and queries the local store.
- **`version` stays `"1"`.** The parser never read it, so a bump enforces
  nothing on old binaries; unknown-key refusal protects future additions.
- **`kind` defaults to `text`**, so every existing entry parses unchanged.

Compatibility: no `backend:` = `type: local` = today's resolution and store.
Three intended breaks hit local setups in Phase 1 (USING.md gets a migration
note):

1. A stray or misspelled key fails to load
   (`unknown key 'secrests' in .secretov.yaml`) instead of being ignored.
2. A `vars:` or `env_var_name` using a newly denied name
   (`GOOGLE_APPLICATION_CREDENTIALS`, any `CLOUDSDK_*`, `AWS_PROFILE`, ...;
   see Deny list) fails to load.
3. A `projects.yaml` failing the owner/mode check (e.g. a group-writable
   `~/.config/secretov`) is refused wherever it is read.

Old-binary wart (accepted): an old binary ignores `backend:`, `kind:` and
`path:` and reads the local store (kv `key:` as a raw store key): wrong
values, never leaks. Upgrade before committing a cloud manifest.

## Paths and kinds

Every entry resolves at parse time to a **path** (provider secret, or local
store key) plus, for `kind: kv`, a **field** (the manifest's `key:`). The
entry name is a label: the TUI row, the `ENTRY` in
`secretov set ENTRY -p NAME -e ENV`, and the name in error text.

| | local | AWS | GCP |
|---|---|---|---|
| path | derived `env/project/NAME`, or `key:` (today's rules) | `path:` required | `path:` required |
| `kind: kv` | parse error (text only) | `path:` + `key:` required | `path:` + `key:` required |
| `key:` means | full store key | JSON field (kv only; on text a parse error) | same as AWS |

The `key:` overload is deliberate: a local manifest switched to a cloud
backend fails loudly on text entries rather than misreading.

Validation, at parse time (cloud paths are always explicit, never derived):

- **AWS name**: `^[A-Za-z0-9/_+=.@-]{1,512}$`, in the account of the
  caller's current credentials, in the env's `region` else `backend.region`.
  No manifest field names or selects that account (`AWS_PROFILE` denied,
  injected keys caught by the nested-exec marker).
- **AWS ARN**:
  `^arn:aws:secretsmanager:REGION:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]{1,512}$`.
  Partition `aws` only. The name goes in the JSON body, never the URL.
- **AWS region** (manifest or ARN) must be in a compiled-in table of the
  `aws` partition's regions; the host is `secretsmanager.<listed
  region>.amazonaws.com`. No host is ever built from free text. A region
  newer than the binary is refused: "not in this build's region table;
  upgrade secretov".
- **GCP project** (`backend.project`, env `project`, `P` in a resource name):
  `^[a-z][a-z0-9-]{4,28}[a-z0-9]$`. Project numbers and domain-scoped ids
  (`example.com:proj`) are refused, so a pin compares one form.
- **GCP id**: `^[A-Za-z0-9_-]{1,255}$`, in the env's `project` else
  `backend.project`.
- **GCP resource name**: `^projects/PROJECT/secrets/ID$`, both parts as above.
- GCP reads always use `versions/latest`. Host is always
  `secretmanager.googleapis.com`; the URL path is assembled from validated
  parts only (no `/`, `?`, `#`, `%` can get in).

Kinds:

- **text**: the provider secret's whole string value.
- **kv**: the secret must be a JSON object. Read: the field's value; strings
  verbatim, numbers and booleans stringified (as `vars:`); objects, arrays
  and null refused; a missing field is reported like a missing secret.
  Write: read, set the field (as a JSON string), write back, other fields
  keeping order and value (`nlohmann::ordered_json`). On a missing secret
  `set` creates `{"<key>": "<value>"}`. A non-object value is refused, never
  overwritten. Delete removes the field and writes back; it never deletes
  the provider secret.
- **Payload decoding** (before kv extraction): AWS `SecretBinary` is refused
  (`binary secret; secretov supports SecretString only`). GCP `payload.data`
  is base64-decoded with `sodium_base642bin` and checked against
  `dataCrc32c` when present. Any value containing NUL is refused (`setenv`
  would truncate it).
- **Lost updates: accepted ceiling.** Neither `PutSecretValue` nor
  `addVersion` takes a compare-and-swap, so concurrent kv edits to one
  secret can drop one, and text writes are last-writer-wins. `ponytail:`
  AWS `VersionStage` checks or GCP etags if it bites.

Writes per provider:

| | AWS | GCP |
|---|---|---|
| `set` | `PutSecretValue`; on `ResourceNotFound` and a name path → `CreateSecret`; an ARN path cannot be created ("ARN paths name existing secrets; create it in its account first"). `ClientRequestToken` from `randombytes_buf`. Pending deletion: see below | `addVersion` (response names new version N); on 404 create (automatic replication) then add; then destroy ENABLED versions numbered **lower than N**, never higher (each active version bills; a concurrent writer's newer version survives; `versions/latest` never points at a destroyed version). A failed destroy (denied, unreachable or other) warns, does not fail the `set` |
| `remove` | `DeleteSecret` with the 7-day recovery window | `DELETE` secret (all versions) |

**AWS pending deletion.** A deleted secret stays recoverable, its name
taken, for 7 days. For a text entry the TUI delete confirm says
`recoverable for 7 days (AWS)` and CLI `delete` output says `recoverable
until <DeletionDate>` (from `remove`'s return). A kv delete never calls
`DeleteSecret`, so it shows no window. Any call on that name (read, text
`set`, the kv read before a write) gets `InvalidRequestException` "marked
for deletion"; aws.cpp raises `PendingDeletion` with the date from one
`DescribeSecret` (`DeletedDate`, shown as-is; Phase 3 tests it against a
real deletion and fixes the label if it is the request time). If
`DescribeSecret` fails, `pending_until` is empty, messages say `pending
deletion (date unavailable)`, and the kind stays PendingDeletion. Then:

- Interactive (CLI stdin is a tty, or the TUI): `pending deletion until
  <date>; restore and overwrite? [y/N]`. Yes → `RestoreSecret`, then the
  write (kv: re-read, set the field, write back); a write failing after the
  restore leaves the secret restored with its old value (no rollback). No
  or EOF → nothing written; CLI exits non-zero, TUI status bar says `not
  saved`.
- Non-interactive (stdin not a tty): refused with `run 'secretov set ENTRY
  -p NAME -e ENV' at a terminal to restore and overwrite, or wait until
  <date>`.
- Reads report it as missing, with the date. Text `delete` of it says
  `already pending deletion until <date>`, exit 0 (the requested state
  holds); kv `delete` says the same and exits non-zero (a restore would
  bring the field back).

## Backend interface

```cpp
// src/backend.hpp
struct BackendError : std::runtime_error {
    enum class Kind { NotFound, Denied, NoCredentials, Unreachable, PendingDeletion };
    Kind kind;
    bool maybe_applied = false;   // Unreachable after the request was sent
    std::string pending_until;    // PendingDeletion only
};

struct Fetched {
    std::map<std::string, std::string> values;
    std::map<std::string, BackendError> failures;   // NotFound, Denied, PendingDeletion
};

// Paths are resolved references: a local store key, an AWS name or ARN, a GCP
// id or resource name. Values are opaque strings; kv fields are the front end's job.
class Backend {
public:
    virtual ~Backend() = default;
    virtual Fetched get_many(const std::vector<std::string>& paths) = 0;
    virtual void set(const std::string& path, std::string_view value) = 0;   // create or replace
    virtual std::optional<std::string> remove(const std::string& path) = 0;   // AWS: DeletionDate
    virtual void restore(const std::string& path);   // AWS only; default throws logic_error
};
std::unique_ptr<Backend> open_backend(const BackendConfig&, const Paths&);
```

`get_many` attempts every path: per-path NotFound, Denied and
PendingDeletion go in `failures`; anything else (NoCredentials,
Unreachable, throttling) throws and aborts the batch. Callers report
Denied first, then PendingDeletion with each date, then NotFound.

- **Paths, not secretov keys, cross the seam.** `SecretEntry::key` becomes
  `path` plus optional `field`. kv extraction and read-modify-write live once
  in the front end; neither backend knows about JSON fields.
- **`get_many` replaces `get` and `getprefix`** for manifest resolution.
  Callers pass exactly the declared paths; nothing on the developer path
  lists (GCP `secretAccessor` has no `secrets.list`; AWS `ListSecrets` cannot
  be scoped by ARN prefix). `exec` collects distinct paths, calls `get_many`
  once, then extracts fields. `LocalBackend` keeps today's
  one-`getprefix`-per-prefix grouping (moved out of `cmd_exec`), so the wire
  protocol does not change.
- **No `list`, `check_set` or capability probes.** Cloud listings come from
  declared entries (`list -p/-e` prints name, kind, path and key); store-wide
  listing stays today's local `DaemonClient` call. `import` stays local and
  keeps `check_request`; cloud size limits (64 KiB) come back as provider
  errors. Permission is learned by trying. "Unsupported" is settled before
  any call: `open_backend` throws `backend 'aws' not compiled in (rebuild
  with -DSECRETOV_BACKEND_AWS=ON)`; `init`, `daemon`, `rotate`, `passwd` are
  local-store commands, not `Backend` methods.
- **Write target is front-end logic**, a pure function of the parsed entry:
  `write_target(entry, backend)` → `aws-account:123456789012`,
  `gcp:acme-secrets`, or none (local, AWS name paths). The pin check runs on
  it before any I/O. Display text is a separate string, never parsed back.
- **Raw-key commands stay local**: `get KEY`, `set KEY`, `delete KEY`
  without `-p`/`-e`, raw-only `exec --secret`, bare `secretov tui`. Cloud
  needs `-p`/`-e` (`tui -p`).

Error taxonomy:

| Kind | local | AWS | GCP |
|---|---|---|---|
| NotFound | `kErrNotFound` | `ResourceNotFoundException` | 404 (only when the caller has access) |
| Denied | — | `AccessDeniedException` | 403 `PERMISSION_DENIED`, worded "denied or does not exist" |
| NoCredentials | `kErrInvalidToken`, missing token file | none found, profile without static keys, `UnrecognizedClientException`, `InvalidSignatureException` (bad secret key, or clock skew: "Signature expired"), `ExpiredTokenException` | no ADC file, unsupported credential type, refresh failed, 401 |
| Unreachable | `DaemonUnreachable`; `maybe_applied` = stage `Sent` | curl connect/DNS/TLS/timeout; `maybe_applied` once the body was sent | same |
| PendingDeletion | — | `InvalidRequestException` "marked for deletion" | — |

Everything else (throttling, malformed replies, kv shape errors) is a plain
`runtime_error` with the provider's code and message. Error text is built
from reply fields only, control characters stripped, never the raw body: AWS
code from `__type` with anything up to `#` stripped, message from `Message`
or `message`; GCP `error.status` and `error.message`. `maybe_applied` keeps
today's TUI "may still be saved/deleted" wording for remote timeouts.

### Personas

| Path | Calls | On Denied |
|---|---|---|
| `exec`, `get ENTRY -p/-e` | `get_many` (distinct paths) | One line before anything runs: `not readable with your credentials: A, B (needs <permission>)`, the permission taken from the provider message (`secretsmanager:GetSecretValue`, `kms:Decrypt`, `secretmanager.versions.access`), parenthetical omitted when none is named. Non-zero exit, nothing injected. |
| `list -p/-e` (cloud) | none: declared entries | — |
| `set ENTRY -p/-e`, `delete ENTRY -p/-e` | nested-exec check, pin check; kv: `get_many` then `set`; text: `set`/`remove` | `this is an administrator action on gcp:acme-secrets; your credentials lack secretmanager.versions.add on dev-db.` |
| `import` (cloud) | none | Refused before I/O: `import is local-only for now; add entries to .secretov.yaml by hand, then 'secretov set ENTRY -p NAME -e ENV'`. |
| TUI reveal/copy | `get_many({path})` | Status-bar message; session continues. |
| TUI write | nested-exec and pin check, then as `set`/`delete` | Status-bar warning (busy/stale chip style); the session flips to read-only (edit/delete greyed, `read-only: write denied by aws`). A pin refusal is **not** Denied: the status bar shows the exact `projects.yaml` line and the session stays writable for pinned and AWS-name-path entries. A nested-exec refusal flips the whole session to read-only (`read-only: AWS credentials set by a parent 'secretov exec'`). |

- `set`/`get`/`delete ENTRY -p/-e` on a cloud manifest need `ENTRY`
  declared: `declare 'ENTRY' in .secretov.yaml first`. On a local manifest
  the new `get`/`delete` flags resolve as `set` does today.
- `exec --secret KEY[=ENVVAR]` without `-p`/`-e` skips the manifest and
  reads the local store, as today, even inside a cloud project directory.
  Combined with `-p`/`-e` that resolve a cloud manifest it is refused
  (`--secret names raw local-store keys; this manifest uses aws`).
- Export order after fetching is today's: `vars:`, manifest secrets, then
  `--secret`, so `--secret` still overrides a manifest var (client.cpp:479).
- TUI: `secretov tui -p NAME` (new) on a cloud manifest shows that project
  across its envs; on a local manifest it is refused (`tui -p is for cloud
  manifests; run 'secretov tui'`). The tree comes from declared entries: `build_rows` gets
  synthesized `env/project/NAME` keys (so `tui_edit` is untouched) and a row
  maps back to its path and field. Nothing is fetched until reveal or copy.
  Add is greyed (`add entries to .secretov.yaml by hand`). The status bar
  shows the selected env's location (`aws:us-east-1`, `gcp:acme-secrets`)
  where it shows `socket_path()` today.

## Credentials

Never a login, a provider CLI, stored credentials, or credential settings
from the manifest. URL-valued fields in credential files are ignored.

**AWS**
1. `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (+ `AWS_SESSION_TOKEN`)
   from the caller's env. One of the pair without the other is an error.
2. Else static keys from `$AWS_SHARED_CREDENTIALS_FILE`, else
   `~/.aws/credentials`; section `$AWS_PROFILE`, else `default`;
   `aws_access_key_id`, `aws_secret_access_key`, `aws_session_token`.
   Minimal INI reader (sections, `key = value`, `#`/`;` comments).
   `~/.aws/config` is not read.
3. Else NoCredentials. SSO, assume-role, `credential_process`, IMDS and
   container credentials are not read; expired session tokens are not
   refreshed. The message names what was checked and the way out:
   `aws: no credentials for profile 'dev' (checked AWS_ACCESS_KEY_ID, ~/.aws/credentials [dev]). SSO, assume-role and credential_process profiles are not read; export AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY/AWS_SESSION_TOKEN into your environment yourself.`

**GCP**
1. ADC file: `$GOOGLE_APPLICATION_CREDENTIALS`, else
   `${CLOUDSDK_CONFIG:-$HOME/.config/gcloud}/application_default_credentials.json`.
2. `type: authorized_user` only: one refresh-token form POST to
   `oauth2.googleapis.com/token` (fixed; `token_uri` in the file ignored).
   Other types: `gcp: unsupported credential type 'service_account' in
   <file>; only authorized_user (gcloud auth application-default login) is
   supported`. No file: `gcp: no credentials (GOOGLE_APPLICATION_CREDENTIALS
   unset, <adc path> missing); run gcloud auth application-default login`.
3. `X-Goog-User-Project` from `GOOGLE_CLOUD_QUOTA_PROJECT` or the file's
   `quota_project_id`.

Tokens and keys live in process memory for one invocation, are
`sodium_memzero`'d on teardown, never written to disk.

## Build and feature flags

- Options `SECRETOV_BACKEND_AWS` and `SECRETOV_BACKEND_GCP`, both OFF.
  Either ON: `find_package(CURL REQUIRED)`, `src/backends/http.cpp`, link
  `CURL::libcurl`. Each ON adds its `src/backends/<name>.cpp` and
  `SECRETOV_HAVE_<NAME>=1`.
- libcurl from the system package (`libcurl4-openssl-dev` or equivalent),
  never vendored, dynamically linked; `get-deps.sh` does not change. A host
  without it fails at configure time. TLS is the system libcurl's;
  verification always on.
- `src/backends/` sits outside the non-recursive `src/*.cpp` glob
  (CMakeLists.txt:88), so an OFF backend is never compiled.
- `open_backend` is an `#if`-guarded switch, not static self-registration (a
  STATIC library drops unreferenced registrars). The parser knows all three
  names: a typo is a parse error, a known-but-absent name gets the rebuild
  hint. `secretov --version` lists compiled-in backends.
- No vendor SDKs. SigV4 on libsodium's `crypto_hash_sha256` and
  `crypto_auth_hmacsha256`; base64 via `sodium_bin2base64`/`sodium_base642bin`;
  CRC32C a ~15-line bitwise loop; bodies via nlohmann/json. libcurl is the
  only new dependency, and only when a cloud backend is ON.
- `just setup` passes `CMAKE_ARGS` through (e.g. `-DSECRETOV_BACKEND_AWS=ON`).

## Security deltas vs DESIGN.md

- **Transport and network.** "The unix socket is the only transport" stays
  true for the daemon; the new interface sits above transport. New: outbound
  TLS from client processes (`exec`, `tui`, `set`, ...) to fixed provider
  hosts, no listener. The daemon and its sandbox
  (`RestrictAddressFamilies=AF_UNIX`) are untouched; remote calls run
  client-side, where the caller's credentials are. secretov ignores
  `AWS_ENDPOINT_URL*`, `AWS_CA_BUNDLE` and `AWS_REGION`/`AWS_DEFAULT_REGION`
  even from the caller; libcurl honors the caller's proxy env.
- **Request-target invariant.** A request's host and resource come only from
  the manifest's validated location fields and paths; its identity and proxy
  only from the caller's own environment and credential files. Manifest
  `vars:` and fetched values reach only the `exec` child, after every fetch;
  secretov never applies them to its own environment. Today `cmd_exec`
  `setenv`s `vars:` before the `getprefix` loop (`export_env_var`); Phase 1
  moves all exports after `get_many`, keeping today's order among them.
  On the wire, http.cpp sets `CURLOPT_FOLLOWLOCATION` off,
  `CURLOPT_PROTOCOLS_STR` and `CURLOPT_REDIR_PROTOCOLS_STR` to `"https"`,
  `VERIFYPEER`/`VERIFYHOST` on, and treats any 3xx as an error, so
  credentials never follow a redirect.
- **Nested-exec marker.** A hostile manifest can put an attacker's AWS keys
  into the `exec` child (literal `vars:`, or a value fetched from an
  unpinned foreign ARN); a `secretov set` inside that child (`exec --
  $SHELL`, a just recipe) would then write a name path into the attacker's
  account. So `exec` sets `SECRETOV_INJECTED=<comma-separated names it set>`
  in the child (appended to an inherited value; manifests cannot set
  `SECRETOV_*`). A secretov that took credential step 1 (env vars) while
  any of `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
  is listed there refuses every cloud write: `refusing to write: AWS
  credentials in this environment were set by a parent 'secretov exec'; run
  outside it`. Reads proceed (they only feed a child). GCP credential
  selection is denied outright and every GCP write is pinned. Cost: a
  project that injects its own AWS keys via `exec` cannot run secretov
  writes inside that child; run them outside it. Ceiling: a child that
  unsets the marker is the repo's code running as the user (ceiling #1).
- **Path validation is a trust boundary**, at parse time: a hostile
  manifest fails before any credential is loaded.
- **Write-target pins.** For ARN paths and every GCP path the manifest
  chooses where a write goes; in a hostile checkout, `set` or a TUI edit
  could upload the victim's values to a project the attacker granted write
  on. Writes there require a pin in the local, uncommitted
  `~/.config/secretov/projects.yaml`:

  ```yaml
  write_targets:                  # trusted write destinations, all projects
    - aws-account:123456789012    # account, from ARN paths
    - gcp:acme-secrets            # project: env project, backend.project or projects/P/...
  projects: { flows-admin: { root: "${HOME}/workspace/flows-admin" } }
  ```

  | Path | `write_target` | Pin needed | Shown as |
  |---|---|---|---|
  | local | none | no | today's output |
  | AWS name | none | no; nested-exec check instead | `aws:<region> (account of your current credentials)` |
  | AWS ARN | `aws-account:ACCOUNT` | yes, even your own (no `GetCallerIdentity`) | `aws-account:ACCOUNT` |
  | GCP id / resource name | `gcp:PROJECT` | yes | `gcp:PROJECT` |

  - Pins gate writes only (`set`, `delete`, TUI edit/delete, the kv
    read-modify-write), checked before any I/O. Reads are unpinned: SigV4
    never sends the secret key and a GCP token goes only to
    `googleapis.com`, and a hostile read only feeds the child (as `vars:`).
    Accepted: a foreign read shows your principal in its audit logs.
  - One global list, not per project: the threat is the destination. AWS
    pins name the account, not the region (the account owner owns every
    region).
  - Refusal names the exact line:
    `refusing to write db-password (env dev) to gcp:acme-secrets: not a trusted write target. The manifest chose it; if you trust it, add this line under write_targets: in /home/u/.config/secretov/projects.yaml:  - gcp:acme-secrets`.
  - No auto-pin, trust-on-first-use or `--trust` flag: a hostile manifest
    must not get trusted by a keypress or a command its README suggests.
  - `projects.yaml` becomes trust-bearing, so it is read only through
    `read_manifest_text`'s owner/mode check (today `registry_project_root`
    calls `YAML::LoadFile`). A failed check is an error wherever the file is
    read (break 3).
  - Every write and delete shows target **and full resolved path** (plus
    `#field` for kv) in CLI output and the TUI confirm:
    `→ aws:us-east-1 (account of your current credentials) prod/payments/stripe`,
    `→ gcp:acme-secrets dev-db#password`. Pins cover the destination, not
    which secret in it: an entry labelled `dev-scratch` with
    `path: prod/payments/stripe` can aim at any of the caller's own
    secrets, as a local `key:` can name any scope (DESIGN.md).
- **Out of scope.** Securing the host, and programs (the `exec` child
  included) that read the environment or credential files and send them
  elsewhere (ceiling #1: same-UID code can already use ambient cloud
  credentials; secretov adds no exposure and removes none).
- **At rest.** The provider's protection plus the local credential files'
  permissions. No passphrase barrier; `rotate`/`passwd`/auto-rotation/`lock`
  (#32) are local-store only.
- **argv.** Values never appear in argv; no subprocess for backends. Key
  names may appear in GCP request URLs, as they do in the manifest.
- **Caching.** None, of values or tokens: a credential load or token refresh
  per invocation. `get_many` is sequential over one keep-alive handle per
  host (`ponytail:` ~30–80 ms per path after TLS, a 30-path `exec` ~1–2 s;
  `curl_multi` or `BatchGetSecretValue` when it hurts).
- **Memory.** Best-effort `sodium_memzero` on our copies of credentials,
  tokens, response buffers and kv objects. libcurl/OpenSSL buffers and
  nlohmann parse trees join the "client processes' copies" ceiling;
  processes stay non-dumpable.
- **Deny list.** Principle widened from "load code or config, or redirect
  traffic through a proxy or CA of the manifest's choosing" to traffic **or
  credential loading** through an **endpoint, proxy, CA or file** of the
  manifest's choosing, plus names that **select the credentials a nested
  secretov would write with**. Additions:
  - prefixes `AWS_ENDPOINT_URL` (covers `_*`) and `CLOUDSDK_`. The prefix
    over-denies harmless ones (`CLOUDSDK_CORE_PROJECT`, `_CORE_ACCOUNT`,
    `_COMPUTE_REGION`); accepted, since every gcloud property is a
    `CLOUDSDK_*` variable and many are endpoint, proxy, CA or file valued,
    so a named list would lag, as with `GIT_`.
  - `AWS_EC2_METADATA_SERVICE_ENDPOINT`, `AWS_CONTAINER_CREDENTIALS_FULL_URI`,
    `AWS_WEB_IDENTITY_TOKEN_FILE`, `GOOGLE_APPLICATION_CREDENTIALS`,
    `GOOGLE_CLOUD_UNIVERSE_DOMAIN` (hosts are `<service>.<universe
    domain>`), `GCE_METADATA_HOST`, `GCE_METADATA_IP`.
  - `AWS_PROFILE` picks the account a nested secretov's name-path write
    lands in; `AWS_DEFAULT_PROFILE` is denied with it (owner decision, Q8)
    because other AWS tools use it as a fallback. Cost: a manifest cannot
    pick a profile for its child's own AWS tooling.
  - Already denied: `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE`,
    `AWS_CA_BUNDLE`.

  Not denied: `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` (fixed link-local
  host), `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES` (acts only on a
  credential file the manifest cannot choose), `GOOGLE_CLOUD_QUOTA_PROJECT`
  (billing header only; host and resource are unchanged and the caller must
  hold `serviceusage.services.use` on it), and
  `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN` (they hold
  a secret, not a loader path; injecting them is a core use case, as with
  `kCredentialNames`; the marker covers their misuse against secretov).

## Code layout and size

| File | Est. lines |
|---|---|
| `src/backend.{hpp,cpp}`: interface, `LocalBackend` (prefix grouping from `cmd_exec`), `open_backend` | 110 |
| `src/backends/http.{hpp,cpp}`: keep-alive handle per host, 5 s connect / 15 s total, 64 MiB cap, https-only, no redirects, scrubbed buffers, reply-field errors | 125 |
| `src/backends/aws.cpp`: SigV4 ~110, region table ~25, env + INI credentials ~70, ops + `SecretBinary` refusal ~105, pending deletion (`DescribeSecret`, `RestoreSecret`) ~25 | 335 |
| `src/backends/gcp.cpp`: ADC refresh ~60, ops + lower-version cleanup ~110, base64 + CRC32C ~20 | 190 |
| `manifest.{hpp,cpp}`: backend block, per-env location, unknown keys, kind/path/key, validation, `write_target`, `write_targets:` through the trust check, deny list | +195 |
| `client.cpp`: route via `Backend`, export reorder + `SECRETOV_INJECTED`, nested-exec check, `--secret` refusal, `get`/`delete -p/-e`, kv extract + read-modify-write, pin check + target/path display, restore prompt, cloud `list`/`import` | +155 net |
| `tui.cpp`: `tui -p`, declared-entry tree, add greyed, read-only flip, pin refusal, target + path and 7-day window in confirms, restore prompt | +115 net |
| CMake + justfile | +15 |

About **1,240 production lines, +24% on today's 5,095** (`wc -l src/*` at
f5edf14, 17 files). Tests ~300 on today's 1,645 (+18%): SigV4 known-answer
vectors from the AWS docs, path/project/region validation, INI parsing,
payload decoding, kv extract and read-modify-write, pin check, nested-exec
marker, error classification from canned reply bodies, deny list. Docs
(DESIGN, USING, SECURITY) ~180 lines.

## Phased plan

Phase 1 lands all syntax at once, since unknown-key refusal freezes it.

1. **Seam only.** `Backend` + `LocalBackend`; `client.cpp` and `tui.cpp` on
   it; export reorder and `SECRETOV_INJECTED`; typed errors; `backend:`
   block, per-env location, `kind`/`path`/`key`, validation with the region
   table, `write_targets:` parsed and `projects.yaml` through the trust
   check (`local` works, `aws`/`gcp` give "not compiled in"); unknown-key
   refusal; deny-list additions; declared-entry `list -p/-e` and refusals
   of `import` and `exec --secret` on non-local manifests (pure front-end
   checks on `backend.type`); DESIGN.md amendments. Behaviour unchanged
   except the three breaks and the new `SECRETOV_INJECTED` variable in
   `exec` children; tests for those added, all others and `smoke_test.sh`
   pass.
2. **AWS read path.** libcurl option and http.cpp policy, SigV4 + KATs,
   credentials, `get_many`, PendingDeletion classification (+
   `DescribeSecret` date), payload decoding and kv extraction → `exec` and
   `get ENTRY -p/-e` work. Cloud `set`/`delete`/`tui -p` are refused ("not
   yet supported"), so no write path exists before pins and the nested-exec
   check. Manual check against a sandbox account with one read-only and
   one admin policy.
3. **AWS admin path.** `set`/`delete` (text and kv), pending-deletion
   restore, nested-exec check, pins and target/path display, `tui -p` with
   declared tree, read-only flip and pin-refusal message.
4. **GCP.** Read then admin, same shape.
5. **Docs.** USING.md (backend block, kinds and paths, credentials, pins,
   personas, new `get`/`delete`/`tui` flags, AWS 7-day delete, IAM policy
   snippets, migration note for the three breaks), SECURITY.md entries for
   the new ceilings. AWS snippets: admin adds `DescribeSecret` and
   `RestoreSecret` to the write actions; read-only is `GetSecretValue` +
   `kms:Decrypt`, optionally `DescribeSecret` (pending-deletion dates).

## Alternatives considered

- **Derived cloud paths** (provider names from `env/project/NAME`, segment rule,
  GCP `--` mapping). Dropped: explicit paths fit existing secrets, allow ARNs
  and kv bundles, and need no reversible mapping.
- **Per-key vs bundle as a manifest-wide layout.** Superseded by per-entry
  `kind`: a team picks per secret, with one code path.
- **AWS credentials via `aws configure export-credentials`.** Covers SSO and
  assume-role with no auth logic. Not chosen: runtime dependency on the AWS CLI
  and a subprocess; users who need those profiles export credentials
  themselves.
- **Vendored libcurl.** No-sudo builds, but the TLS backend would be vendored
  too and the binary grows.
- **Trust-on-first-use or auto-pinning.** Less friction, but the first use in a
  hostile checkout is exactly the one to refuse.
- **Unknown-key refusal only with `backend:`.** Keeps every local manifest
  loading, but a future key on a local manifest would again be ignored by the
  binary that should refuse it.
- **Nested-exec gap as a ceiling.** No code, but a nested secretov is still
  secretov, and no manifest-set variable may redirect it.
- **Account guard** (`GetCallerIdentity` / expected project before writes).
  One call per admin op. Not chosen: AWS name paths go to the caller's own
  account (manifest-chosen credentials are denied or caught by the marker),
  and pins cover ARNs and GCP without a call.
- **Subprocess helpers** (`secretov-backend-aws`, Go + official SDKs). Best
  credential fidelity, no new C++ dependencies. Not chosen: bends "one
  binary"; Go as a second language and the Google SDK's gRPC/protobuf tree; Go
  cannot scrub secret memory; a versioned stdin/stdout protocol is permanent
  surface. The seam leaves room for a `PluginBackend` later.
- **Vendor C++ SDKs** (aws-sdk-cpp, google-cloud-cpp). Full credential chains,
  but ~14 CRT submodules and up to an hour of build, or gRPC, protobuf and
  Abseil, for a handful of operations.
- **Shell out to `aws` / `gcloud`.** No build dependencies, but ~100 ms to ~1 s
  of Python start per call, errors as stderr text, output drift across
  versions.
- **Backends inside the daemon.** The daemon is `AF_UNIX`-only and does not
  see the caller's credentials; it would have to be loosened and would then
  hold cloud credentials for every caller. It exists to unlock a local store,
  which cloud backends lack.
- **Capability reporting and permission probes.** AWS has no cheap
  equivalent, probes go stale, and the only optional operations are
  local-store commands. Learn by trying, degrade on Denied.
- **Manifest `version: "2"`.** Old binaries ignore `version` as they ignore
  `backend:`.

## Decisions log

All 2026-10-09, owner.

- Q1 secret layout → per-entry `kind` (text/kv) with explicit cloud paths.
- Q2 HTTP dependency → system libcurl, never vendored.
- Q3 AWS credentials → env vars + shared credentials file; no CLI, no SSO.
- Q4 GCP credentials → ADC `authorized_user` only.
- Q5 commands without a scope → raw `get`/`set`/`delete KEY`, raw `exec --secret`, bare `tui` stay local; `--secret` with a cloud manifest refused.
- Q6 per-env location → allowed: env `region:` (aws) / `project:` (gcp).
- Q7 threat stance → write-target pins; no manifest-set variable may redirect secretov.
- Q8 `AWS_PROFILE`/`AWS_DEFAULT_PROFILE` in manifests → denied.
- Q9 AWS delete → `DeleteSecret`, 7-day window stated on delete; write to a pending name: interactive asks to restore and overwrite (`RestoreSecret`, then write), non-interactive refuses with the restore hint.
- Q10 compatibility → old-binary wart and the three local breaks approved.
- Q11 DESIGN.md amendments (Security deltas) → approved.
- Q12 local manifests → keep derived keys; `key:` dual meaning (store key / kv field) kept.
- Q13 GCP full resource names → allowed, project ids only, pinned on write.
- Q14 pin shape → one global `write_targets:`; AWS by account, GCP by project.
- Q15 AWS scope → partition `aws` only, compiled-in region table.
- Q16 nested secretov → `SECRETOV_INJECTED` marker; injected AWS credentials refuse cloud writes.
