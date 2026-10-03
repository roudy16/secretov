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
whole (multi-line values work). From a script, read the value into a variable
first so it never lands in shell history:

```sh
read -rs v; printf %s "$v" | secretov set DB_URL -e dev; unset v
```

Never write a literal value into a `printf` (or any command line): the shell
saves it to history in plaintext.

`get` prints to your terminal, so the value stays in scrollback; prefer `exec`,
or pipe `get` straight into what needs it.

`set` creates or replaces; there is no separate update command. `get` and
`delete` still take a raw full key (`env/project/KEY`) — only `set`, `list`,
`exec`, and `import` accept `-p`/`-e`.

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

- **Permissions.** The `.secretov.yaml` must be a regular file owned by you
  and not group- or world-writable; its directory (and, for a symlink, the
  target's directory) must be owned by you or root and not group- or
  world-writable. Otherwise every command that reads it (`exec`, `list`,
  `set -p/-e`, `import`, `--dry-run`, including `-p` registry lookups)
  refuses with the fix, e.g.
  `refusing manifest directory '/path': writable by group or others; fix with: chmod g-w,o-w '/path'`.
  A default umask of 0002 makes new project dirs group-writable; run the
  `chmod` it prints.
- **Discovery** walks up from the current directory only through directories
  you own, so a manifest in `/tmp`, `/home`, or `/` is never picked up. A bad
  nearer manifest is an error; secretov never falls back to one further up.
- **Denied names.** `vars:` keys and `env_var_name` cannot be `LD_*`,
  `DYLD_*`, `SECRETOV_*`, `BASH_ENV`, `ENV`, `IFS`, `NODE_OPTIONS`,
  `PYTHONSTARTUP`, `PYTHONPATH`, `PERL5OPT`, `PERL5LIB`, `RUBYOPT`,
  `JAVA_TOOL_OPTIONS`, `GIT_SSH_COMMAND`, or `GIT_EXEC_PATH` — they load code
  into the child. `PATH` is allowed. `--secret KEY=VAR` on your own command
  line is not filtered.
- **Program lookup.** `exec` resolves the command against *your* `PATH`
  before applying any manifest var, then runs that exact file. A manifest
  `PATH` still reaches the child's environment but cannot choose which program
  starts. A program not found fails before any secret is fetched; a script
  must have a `#!` line (no `/bin/sh` fallback).

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
| `project 'X' is not in .../projects.yaml` | Step 3 skipped | Add the registry entry, or run from inside the project |
| `no .secretov.yaml found from the current directory upward` | Not in the project, no `-p` | `cd` to the project, or pass `-p NAME` |
| `no environment: pass -e ENV, set SECRETOV_ENV, or add default_env` | Step 4 skipped | Pass `-e`, or add `default_env` |
| `environment 'X' not found in <manifest>` | No such env block | Import that env, or fix the `-e` value |
| `already in store (pass --overwrite to replace)` | Re-importing existing keys | `--overwrite` if replacing is intended |
| `missing secrets: ...` | Manifest names keys the store lacks | Import them, or `set` each one |
| `'X' (env dev) is set in both vars and secrets` | Same variable defined twice | Remove one of the two definitions |
| `var 'X' (env dev) must be a scalar value` | A nested map/list under `vars:` | Use a plain scalar |
| `invalid token` | Client/daemon token mismatch | Daemon restarted against a different config |
| `refusing manifest[ directory] '...': writable by group or others` | Manifest or its dir is group/world-writable | Run the `chmod g-w,o-w` it prints |
| `refusing manifest[ directory] '...': owned by uid N, not you` | Someone else's manifest or dir | Remove it, or chown it to yourself |
| `... cannot be set from a manifest` | A denied name under `vars:` or `env_var_name` | Rename it, or pass it on your own command line |
| `cannot run 'X': not found in PATH` | `exec` program missing from *your* PATH | Install it, or give a path with a `/` |
| `daemon already running at ...` | A second `secretov daemon` | Use the running one, or stop it first |
| `cannot prompt from a background process` | A prompt from a `&` job | Run it in the foreground, or pipe the input |
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
