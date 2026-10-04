# Using secretov

For **consumers** — humans and agents working in *some other project* who need
that project's secrets. Nothing here is about building or modifying secretov
itself; that is `AGENTS.md` and `DESIGN.md`.

The whole model: secrets live in one encrypted store behind a local daemon. A
project keeps a committable `.secretov.yaml` manifest that maps secret names to
environment variable names, and `secretov exec` injects them into a child
process. No `.env` file on disk, no values in the repo.

## Before anything else: is the daemon up?

```sh
secretov list >/dev/null && echo up
```

If you get `daemon not running at /run/user/1000/secretov.sock ?`, start it:

```sh
~/workspace/roudy16/secretov/scripts/service start
```

The daemon starts at graphical login, takes its passphrase from the session
keyring, and stops at graphical logout, so this is only needed if it was
stopped or failed. It is non-interactive once the keyring holds the
passphrase; if it prompts, a human must answer. Without an active graphical
session (e.g. over ssh) `scripts/service start` fails; a human can run
`secretov daemon` in a foreground terminal instead. Only one daemon runs per
socket: a second one exits with `daemon already running at ...`.

**Upgrading secretov itself:** the first daemon start after upgrading past
the envelope-encryption change migrates an older store file in place. This is
one-way — back up `~/.local/share/secretov/store` first if you might need to
roll the binary back (see Backup and recovery in README.md).

## Onboard a new project

From the project root, with its `.env` present. Steps 3 and 4 are easy to
forget and neither is automatic.

```sh
cd ~/workspace/roudy16/myproj
```

**1. Import the `.env`.** Creates `.secretov.yaml` and stores each var as
`dev/myproj/VAR`:

```sh
secretov import -p myproj -e dev
```

`-p NAME` names the project; on a fresh project the manifest is created in the
current directory. Existing keys are refused unless you pass `--overwrite`, and
the import is all-or-nothing.

The dotenv parser is strict rather than guessing: a key that appears twice is
an error naming both lines; double-quoted values decode `\n \t \r \\ \"` and
any other backslash escape is an error; an unquoted value loses a trailing
` #...` comment with a warning naming the line (quote the value if the `#`
belongs to it). Variable names on the manifest deny list (see Manifest rules)
fail the import before anything is written.

**2. Check what it wrote.** Names only — never values, so this file is safe to
commit:

```yaml
version: "1"
name: myproj
env:
  dev:
    secrets:
      DB_URL:
        env_var_name: DB_URL
```

**3. Register the project.** `import` does *not* do this, and without it `-p
myproj` fails from anywhere outside the project directory. Hand-edit
`~/.config/secretov/projects.yaml` (`${HOME}` and `${USER}` are expanded):

```yaml
projects:
  myproj:
    root: "${HOME}/workspace/roudy16/myproj"
```

**4. Add a default environment** (optional but recommended). `import` does not
write one, so without it every later command needs an explicit `-e`:

```yaml
default_env: dev      # add near the top of .secretov.yaml
```

**5. Verify, then retire the `.env`.** `--dry-run` prints the variable-to-key
mapping and never prints a value:

```sh
secretov exec -e dev --dry-run
rm .env && echo '.env' >> .gitignore
git add .secretov.yaml
```

## Daily use

```sh
secretov exec -e dev -- npm run dev     # inject this env's secrets, then run
secretov exec -e dev --dry-run          # VAR <- key mapping, no values
secretov list -p myproj -e dev          # keys in one scope
secretov set DB_URL -e dev              # replace one secret (prompts, no echo)
secretov get dev/myproj/DB_URL          # print one value (raw full key)
secretov tui                            # browse/edit interactively
secretov rotate                         # new encryption key (prompts for current passphrase)
secretov passwd                         # change the passphrase (prompts for current + new)
```

Values never come from argv — there is no `set KEY VALUE` form, because argv
is world-readable via `/proc/<pid>/cmdline`. On a terminal, `set` prompts
`Value for <key>:` with echo off and reads one line. Piped stdin is read
whole (multi-line values work). Never paste a multi-line value (a PEM key, a
cert) at the prompt: `set` fails with `more input followed the line` and
discards the rest so it never reaches your shell; pipe it instead
(`secretov set K < key.pem`). The terminal silently cuts a line at 4095
bytes, so a prompted line that long is refused; pipe longer `set` values
(piped passphrase lines are capped at 4096 bytes). An empty line at the `set`
prompt is refused too, so a stray Enter never blanks a key; pipe an empty
value if you mean it. From a
script, read the value into a variable first so it never lands in shell
history:

```sh
IFS= read -rs v; printf %s "$v" | secretov set DB_URL -e dev; unset v
```

Never write a literal value into a `printf` (or any command line): the shell
saves it to history in plaintext.

`get` prints to your terminal, so the value stays in scrollback; prefer `exec`,
or pipe `get` straight into what needs it, or clear scrollback afterwards.

`set` creates or replaces; there is no separate update command. `get` and
`delete` still take a raw full key (`env/project/KEY`) — only `set`, `list`,
`exec`, and `import` accept `-p`/`-e`.

### The TUI

`secretov tui` shows the store as a tree folded on `/`; values stay masked
until you reveal them, and a revealed value re-masks after 60 seconds (the
status bar counts down). `?` (or F1) lists every key in every mode, plus the
socket path and any project-manifest problem; `j`/`k`, arrows, PgUp/PgDn or
the wheel scroll it on a short terminal, any other key closes it.

| Where | Keys |
|---|---|
| tree | `j`/`k` or arrows move, PgUp/PgDn page, `g`/`G` or Home/End top/bottom, `h`/Left fold or go to parent, `l`/Right unfold or go to first child, Enter/Space/`r` reveal or hide (on a folder Enter/Space fold), `c` copy the value, `J`/`K` scroll the detail pane, `/` filter, Esc clear filter and message, `a` add, `e` edit, `d` delete, `R` reload, `?`/F1 help, `q`/Ctrl-C quit (Ctrl-Z does not suspend: resuming would leave safe paste off); mouse: click selects (a folder also folds), wheel moves |
| filter (`/`) | type or paste to narrow, Backspace erase, Ctrl-U erase all, arrows/PgUp/PgDn move, Enter keep the filter, Esc clear it |
| add/edit form | Enter: next field (add name) or save, Tab switch field (add only), Esc cancel, Ctrl-R show/hide the value, Ctrl-U erase to line start, Ctrl-W erase previous word or path segment, Ctrl-A/Ctrl-E line start/end |
| confirm (`[y/N]`) | `y` yes; Enter, Esc, or any other key no |

`c` copies the selected secret's value without revealing it, through the
OSC 52 clipboard escape on the controlling terminal. The terminal must allow
OSC 52 (most do; under tmux, `set -g set-clipboard on`), and a clipboard
manager may keep its own copy of anything copied.

The filter narrows the tree to keys containing the typed text (any case) and
opens every folder with a match; it stays on after Enter and shows in the
status bar. Fold state lives only for the session — nothing about the store's
layout (key names are encrypted at rest) is written to disk.

Run from inside a project, the TUI reads the nearest `.secretov.yaml` with
the same discovery and trust checks as `exec`, marks the keys it references
with `◆`, and shows the env var name(s) each maps to in the detail pane. The
whole store is still shown. A manifest that fails the trust check or does not
parse marks nothing, says why in the status bar at start, and keeps
`◆ refused, see ?` in the list title with the full reason in `?`.

The hint line above the status bar shows the keys for the current mode,
dropping the least-used ones when the terminal is narrow. Long names are cut
with `…` in the tree, and very deep folders stop indenting where the name
would no longer fit; the detail pane shows the full name and the revealed
value wrapped (multi-line values keep their lines), and its title shows
`first-last/total J/K scroll` when they don't fit. A revealed value shows a
tab as `→` and any other control character as `?`. Below 80 columns the tree
sits above the detail pane and the add/edit form and the `[y/N]` question
take the full width; a name too long for the question on screen loses its
middle (`…`) there. The
status bar shows the latest message first (info clears after a few seconds or
the next key, errors at the next key), then a `daemon unreachable` (or
`daemon busy`) marker, the
active filter, the reveal countdown, the key count, and the socket path. The
message comes first: short of room, the socket and key count drop and the
others shorten (`stale` or `busy`, `/filter`, `60s`), and a message still too long gets
up to three rows of its own above them (longer ones end in `…`; warnings such
as the clipboard note come before the key name, so a long name is what gets
cut). A revealed value stays in view on a short detail pane, even when a
long message or a resize shrinks it, until you scroll with `J`/`K`.

The list is fetched at start and after the TUI's own changes; `R` reloads it
after CLI changes. A key deleted elsewhere is noticed on reveal, copy or edit:
the list reloads and the status bar says so. If the daemon stops, the last
tree stays on screen marked `(stale)`, and the status bar says how to start
it, until a request (`R`) succeeds again. Every daemon call gives up after 5
seconds with `daemon busy` (another client holding the daemon's single
connection; the status bar then keeps `daemon busy`, and the tree is not
marked stale) — the CLI too; `rotate`/`passwd` wait 60 seconds. The request is
already queued by then, so the daemon may still carry out a save or delete
once it is free: the TUI says the key "may still be saved/deleted" and `R`
shows what happened (also when the daemon hangs up without replying). A value
too large for the daemon's 1 MiB request limit is refused before it is sent.
At startup the TUI prints how to fix a missing token (`secretov init`), a
stopped daemon (`scripts/service start` or `secretov daemon`) or a busy one
before taking over the screen.

Add starts the name at the selected folder (`dev/api/`); the name is trimmed
and must not start or end with `/` or contain `//` or control characters.
Adding a name that already exists asks before overwriting. After saving, the
new key's folders open and it is selected; after a delete the selection moves
to the nearest key in the same folder. Edit opens with the current value,
masked (one bullet per character, so its length shows; the detail pane does
not show it), at its end, or at its top if it has several lines. Tabs and
other control characters draw nothing in the form, not even a bullet; reveal
the value in the detail pane to see them. Long lines scroll sideways in the
form with the cursor, which shifts every line while the cursor is on a long
one; a value taller than the input shows `line N/total` in the form title. Both refuse an empty value.
A multi-line value (a PEM key) can be pasted into the value field — newlines
are kept but one trailing newline is dropped, as `set` does, and the paste
never submits the form; a paste into the filter is
added to it if it is one line, and any other paste outside a form is ignored.
With the terminal's bracketed paste (all common terminals and tmux) the paste
arrives whole. Without it, an Enter or Tab in the value followed within 50 ms
by more input is kept as a newline or tab, and keys arriving within 100 ms of
a form submit or of the Enter that ends the filter are dropped (`input right
after Enter ignored`), so the rest of a paste never runs as commands or lands
in the name field. Control characters in key names show as `?`.

## Non-secret config: `vars:`

Not everything a project needs is a secret. A log level, a public API URL, a
port — those can live in the manifest itself under `vars:`, injected by `exec`
alongside the real secrets with no store lookup:

```yaml
env:
  dev:
    vars:                                  # plaintext, committed as-is
      LOG_LEVEL: debug
      API_URL: https://dev.example.com
      PORT: 8080
    secrets:
      DB_URL:
        env_var_name: DB_URL
```

```sh
secretov exec -e dev -- sh -c 'echo $LOG_LEVEL $DB_URL'   # debug <the secret>
```

The YAML key is the environment variable name; the value is used verbatim.
Numbers and booleans are stringified, so `PORT: 8080` injects `"8080"`.

> **Anything under `vars:` is committed to the repo in plaintext.** It is not
> encrypted, not in the store, and readable by anyone who can read the
> repository. If a value would matter in a leak, it belongs under `secrets:`.

Write `vars:` by hand — `import` only ever fills in `secrets:`, and it leaves
an existing `vars:` block untouched. `--dry-run` prints these values in full
(they are already public) while still showing secrets only by key. They never
appear in `secretov list`, because they are not in the store.

Defining the same variable in both `vars:` and a secret's `env_var_name` for
one environment is an error — `'X' (env dev) is set in both vars and secrets`
— rather than one silently winning. An explicit `--secret KEY=VAR` on the
command line does override a manifest var.

## Manifest rules

A manifest decides what code runs with your secrets, so secretov only trusts
one that nobody else can change:

- **Permissions.** The `.secretov.yaml` must be a regular file owned by you;
  its directory (and, for a symlink, the target's directory) must be owned by
  you or root. None may be world-writable, and none may be group-writable
  unless the owning group is your private group (your primary group, named
  after you), you are its only member (counting accounts whose primary
  group it is and any other group sharing its gid), and the file or
  directory has no ACL (`ls -l` shows a `+`). Otherwise every command that reads it (`exec`, `list`,
  `set -p/-e`, `import`, `--dry-run`, including `-p` registry lookups)
  refuses with the fix, e.g.
  `refusing manifest directory '/path': writable by group 'roudy', which also includes devuser (its primary group); fix with: chmod g-w '/path', or make 'roudy' yours alone: sudo userdel devuser or sudo usermod -g <another group> devuser (and end any of their processes still running)`.
  An `import` that would create or change the manifest checks the same way,
  and that the directory exists and is writable, before storing anything; a
  symlinked manifest is updated at its target. A default umask of 0002 makes new project dirs
  group-writable, which is fine while your group is private to you. Locking an
  account does not remove it from a group, and removing one does not take the
  group from its processes already running; end them too. Membership is read
  from the passwd and group databases, so a service you give your group
  (systemd `SupplementaryGroups=`) is not seen; don't share your private
  group with anything you would not let write your manifests.
- **Discovery** walks up from the current directory only through directories
  you own, so a manifest in `/tmp`, `/home`, or `/` is never picked up. A bad
  nearer manifest is an error; secretov never falls back to one further up.
- **Denied names** (compared ignoring case). `vars:` keys and `env_var_name`
  cannot be `LD_*`, `DYLD_*`, `SECRETOV_*`, `GIT_*`, `XDG_*`, `NPM_CONFIG_*`,
  `BUNDLE_*`, `GEM_*`, `LUA_*`, `PATH`, `HOME`, `BASH_ENV`, `ENV`,
  `IFS`, `PROMPT_COMMAND`, `PS1`, `PS4`, `ZDOTDIR`, `PAGER`, `PSQL_PAGER`,
  `MANPAGER`, `LESSOPEN`, `LESSCLOSE`, `EDITOR`, `VISUAL`, `GCONV_PATH`,
  `NODE_OPTIONS`, `NODE_PATH`, `PYTHONSTARTUP`, `PYTHONPATH`, `PYTHONHOME`,
  `PERL5OPT`, `PERL5LIB`, `PERLLIB`, `RUBYOPT`, `RUBYLIB`, `JAVA_TOOL_OPTIONS`,
  `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS`, `PYTHONUSERBASE`, `PSQLRC`,
  `SSH_ASKPASS`, `SSH_ASKPASS_REQUIRE`, `KUBECONFIG`, `AWS_CONFIG_FILE`,
  `AWS_SHARED_CREDENTIALS_FILE`, `OPENSSL_CONF`, `OPENSSL_ENGINES`,
  `OPENSSL_MODULES`, `GOFLAGS`, `CLASSPATH`, `MAVEN_OPTS`, `GRADLE_OPTS`,
  `DOCKER_HOST`, `PYTHONWARNINGS`, `PYTHONBREAKPOINT`, `BROWSER`, `PERL5DB`,
  `PHPRC`, `PHP_INI_SCAN_DIR`, `GLIBC_TUNABLES`, `LOCPATH`, `NLSPATH`,
  `SHELLOPTS`, `BASHOPTS`, `R_PROFILE_USER`, `JULIA_LOAD_PATH`, `TCLLIBPATH`,
  `ERL_AFLAGS`, `ELIXIR_ERL_OPTIONS`, `RUSTC`, `RUSTDOC`, `RUSTFLAGS`,
  `RUSTDOCFLAGS`, `GOENV`, `GOROOT`, `GOTOOLCHAIN`, `GOWORK`, `CC`, `CXX`,
  `MAKEFLAGS`, `MFLAGS`, `GNUMAKEFLAGS`, or any `PIP_*`, `UV_*`, `CARGO_*`,
  `RUSTUP_*`, `RUSTC_*`, `DOTNET_*`, `CORECLR_*` (except the credentials
  `CARGO_REGISTRY_TOKEN`, `CARGO_REGISTRIES_<NAME>_TOKEN`, `UV_PUBLISH_TOKEN`,
  `UV_PUBLISH_PASSWORD`, `UV_PUBLISH_USERNAME`) — they make the
  child (or anything it runs) load code or config the manifest picks — nor
  any `*_PROXY` but `NO_PROXY`, `GOPROXY`, `GONOPROXY`, `GOPRIVATE`,
  `GOSUMDB`, `GONOSUMDB`, `GONOSUMCHECK`, `GOINSECURE`, nor `SSL_CERT_FILE`,
  `SSL_CERT_DIR`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `AWS_CA_BUNDLE`,
  `NODE_EXTRA_CA_CERTS`, `NODE_TLS_REJECT_UNAUTHORIZED`, `PYTHONHTTPSVERIFY`,
  or `SSLKEYLOGFILE`, which would let it intercept or read the child's
  requests or fetch code from an index the manifest picks. It is a deny list, so a tool with its own
  loader variable can still slip through. `--secret KEY=VAR` on your own command line is not filtered.
- **Program lookup.** `exec` finds the command on *your* `PATH` (a manifest
  cannot set `PATH`).

## Key naming

Scoped keys are three segments, `env/project/KEY`. The store is a flat map —
the hierarchy is pure naming convention, so nothing is inherited or layered
implicitly. `shared` is a conventional environment name for cross-project
secrets with no special handling:

```yaml
      openai-key:
        key: shared/myproj/openai-key     # explicit full key, any env/project
        env_var_name: OPENAI_API_KEY
```

Environment resolution, in order: `-e ENV` → `$SECRETOV_ENV` → the manifest's
`default_env` → error. Project resolution: `-p NAME` via the registry →
otherwise the nearest `.secretov.yaml` walking up from the current directory
(through directories you own; see Manifest rules).

Add a second environment by importing again: `secretov import .env.prod -e prod`.

## Troubleshooting

| Message | Cause | Fix |
|---|---|---|
| `daemon not running at ... ?` | Daemon down | `scripts/service start`; check `scripts/service status` if it fails |
| `daemon busy: no reply within 5 s` | Another client is holding the daemon's one connection | Find and stop the stuck client: `ss -xp \| grep secretov.sock` shows the peer inode last, `ss -xp \| grep <that inode>` names the holder; then retry |
| `daemon busy: request sent but no reply within 5 s; it may still be applied` | Same, but the request was already queued: a `set`/`delete` lands once the daemon is free | Stop the stuck client, check with `list`/`get` before retrying (an `import` rerun then needs `--overwrite`) |
| `value too large: the request is N bytes, the daemon's limit is 1048576` | A value near or over 1 MiB (JSON escaping counts) | Keep large files out of the store; store a path or a smaller secret |
| `import: VAR: value too large ...; nothing imported` | A `.env` value over 1 MiB once JSON-escaped (a control character counts 6 bytes); every value is checked before anything is stored | Remove or shrink it, then rerun |
| `import: VAR: [json.exception.type_error.316] ...; nothing imported` | A `.env` value that is not valid UTF-8 | Fix the value's encoding, then rerun |
| `project 'X' is not in .../projects.yaml` | Step 3 skipped | Add the registry entry, or run from inside the project |
| `manifest .../.secretov.yaml names project 'X' but registry entry is 'Y'` | The registry's `Y` points at a root whose manifest says `project: X` | Rename the registry entry to `X`, or fix its `root` |
| `no .secretov.yaml found from the current directory upward` | Not in the project, no `-p` | `cd` to the project, or pass `-p NAME` |
| `no environment: pass -e ENV, set SECRETOV_ENV, or add default_env` | Step 4 skipped | Pass `-e`, or add `default_env` |
| `environment 'X' not found in <manifest>` | No such env block | Import that env, or fix the `-e` value |
| `already in store (pass --overwrite to replace)` | Re-importing existing keys | `--overwrite` if replacing is intended |
| `manifest entry 'X' in env 'E' already exists with a different key or env_var_name` | `import` would store `E/project/X`, but the manifest's `X` reads another key or sets another variable | Fix or remove that entry by hand, then rerun |
| `missing secrets: ...` | Manifest names keys the store lacks | Import them, or `set` each one |
| `'X' (env dev) is set in both vars and secrets` | Same variable defined twice | Remove one of the two definitions |
| `var 'X' (env dev) must be a scalar value` | A nested map/list under `vars:` | Use a plain scalar |
| `invalid token` | Client/daemon token mismatch | Daemon restarted against a different config |
| `refusing manifest[ directory] '...': writable by everyone` | Manifest or its dir is world-writable | Run the `chmod` it prints |
| `refusing manifest[ directory] '...': writable by group 'G', which also includes ...` | Group-writable, and another account or group shares G | Run the `chmod g-w` it prints, or the `gpasswd`/`usermod`/`groupmod` commands it prints, then end those accounts' processes |
| `refusing manifest[ directory] '...': writable by group G, which is not your private group` | Group-writable by a group other than your own (G is a gid, or a quoted name when it reuses your gid) | Run the `chmod g-w` it prints |
| `refusing manifest[ directory] '...': writable by group G, which has no group entry` | Group-writable by a gid with no name | Run the `chmod g-w` it prints |
| `refusing manifest[ directory] '...': has an ACL` | Group-writable with an ACL, which may grant write to others | Run the `setfacl -b` or `chmod g-w` it prints |
| `refusing manifest[ directory] '...': group-writable, and its ACL cannot be read` | The ACL query failed | Run the `chmod g-w` it prints |
| `refusing manifest[ directory] '...': owned by uid N, not you` | Someone else's manifest or dir | Remove it, or chown it to yourself |
| `... cannot be set from a manifest` | A denied name under `vars:` or `env_var_name` | Rename it, or pass it on your own command line |
| `cannot run 'X': No such file or directory` | `exec` program missing from *your* PATH | Install it, or give a path with a `/` |
| `daemon already running at ...` | A second `secretov daemon` | Use the running one, or stop it first |
| `cannot prompt from a background process` | A prompt from a `&` job | Run it in the foreground, or pipe the input |
| `more input followed the line on the terminal` | Multi-line paste at a prompt | Pipe it: `secretov set K < file` |
| `socket ... is served by uid N, not ours` | Another user's daemon at your socket path | Check `XDG_RUNTIME_DIR` |
| `dotenv line N: duplicate key` / `unsupported escape` | Ambiguous `.env` | Fix the line it names, then re-import |

## Rules

- **Never commit a `.env`.** `.secretov.yaml` is safe to commit; secret *values*
  live solely in the encrypted store. The one thing it does hold verbatim is
  the `vars:` block — non-secret config only, by definition.
- **Never pass a secret in argv** — stdin only.
- Any process running as your UID can read every secret while the daemon is
  unlocked. That is an accepted design ceiling, not a bug; see `SECURITY.md`.
- A manifest can name any scope (`key:`), so `exec` inside an untrusted
  checkout hands that code your secrets — though you are already running its
  code by then. secretov only refuses manifests that someone *else* can write
  (see Manifest rules); a cloned repo you own is trusted.

Full schema, protocol, and threat model: [DESIGN.md](DESIGN.md).
