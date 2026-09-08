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
~/workspace/roudy16/secretov/scripts/service start   # prompts for the passphrase
```

**This is interactive and must be redone after every reboot.** The daemon
deliberately does not auto-start — it needs a passphrase and a boot-time
service has no tty. An agent cannot start it unattended; ask the human.

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
printf 'new-value' | secretov set DB_URL -e dev   # replace one secret
secretov get dev/myproj/DB_URL          # print one value (raw full key)
secretov tui                            # browse/edit interactively
secretov rotate                         # new encryption key (prompts for current passphrase)
secretov passwd                         # change the passphrase (prompts for current + new)
```

Values are **read from stdin only** — there is no `set KEY VALUE` form, because
argv is world-readable via `/proc/<pid>/cmdline`. Use `printf`, not `echo -n`,
and never put a secret on a command line.

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
otherwise the nearest `.secretov.yaml` walking up from the current directory.

Add a second environment by importing again: `secretov import .env.prod -e prod`.

## Troubleshooting

| Message | Cause | Fix |
|---|---|---|
| `daemon not running at ... ?` | Daemon down (always after a reboot) | `scripts/service start` — interactive, needs the human |
| `project 'X' is not in .../projects.yaml` | Step 3 skipped | Add the registry entry, or run from inside the project |
| `no .secretov.yaml found from the current directory upward` | Not in the project, no `-p` | `cd` to the project, or pass `-p NAME` |
| `no environment: pass -e ENV, set SECRETOV_ENV, or add default_env` | Step 4 skipped | Pass `-e`, or add `default_env` |
| `environment 'X' not found in <manifest>` | No such env block | Import that env, or fix the `-e` value |
| `already in store (pass --overwrite to replace)` | Re-importing existing keys | `--overwrite` if replacing is intended |
| `missing secrets: ...` | Manifest names keys the store lacks | Import them, or `set` each one |
| `'X' (env dev) is set in both vars and secrets` | Same variable defined twice | Remove one of the two definitions |
| `var 'X' (env dev) must be a scalar value` | A nested map/list under `vars:` | Use a plain scalar |
| `invalid token` | Client/daemon token mismatch | Daemon restarted against a different config |

## Rules

- **Never commit a `.env`.** `.secretov.yaml` is safe to commit; secret *values*
  live solely in the encrypted store. The one thing it does hold verbatim is
  the `vars:` block — non-secret config only, by definition.
- **Never pass a secret in argv** — stdin only.
- Any process running as your UID can read every secret while the daemon is
  unlocked. That is an accepted design ceiling, not a bug; see `SECURITY.md`.
- A manifest in a cloned repo can name any scope, so `exec` inside an untrusted
  checkout hands that code your secrets — though you are already running its
  code by then.

Full schema, protocol, and threat model: [DESIGN.md](DESIGN.md).
