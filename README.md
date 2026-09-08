# secretov

A local secrets service for developer environments: one daemon, one CLI,
secrets in one encrypted file instead of scattered `.env` files. Clients
authenticate over a unix socket (peer UID + API token) and can inject
secrets straight into child process environments. See [DESIGN.md](DESIGN.md)
for the threat model and design decisions.

All dev workflows go through `just` (run `just` alone to list recipes):

- `just setup` — fetch vendored deps if needed, configure the build
- `just build` — compile
- `just test` — run tests (ctest)
- `just run [args...]` — run the binary (e.g. `just run daemon`)
- `just install` — install (cmake --install)
- `just clean` — remove the build directory

## Quickstart

```sh
just setup && just build
just run init                      # create store + API token (prompts for passphrase)
just run daemon                    # foreground; prompts for passphrase
printf 'hunter2' | just run set DB_PASS   # creates or replaces
just run get DB_PASS
just run exec --secret DB_PASS -- your-command   # inject into child env
just run tui                       # interactive terminal UI
```

Commands: `init`, `daemon`, `get`, `set` (create or replace; value via stdin
only; `[-p NAME] [-e ENV]` to scope the key), `list`,
`delete`, `rotate` (new encryption key; prompts for the current passphrase),
`passwd` (change store passphrase; daemon must be running), `exec`, `import`,
`tui`.

## Using secretov in another project

If you are here to *use* secretov rather than work on it, read
**[USING.md](USING.md)** — onboarding, daily commands, and troubleshooting,
written for consumers (human or agent).

Scoped secrets are keyed `env/project/KEY`. A `.secretov.yaml` at a project
root maps secrets to environment variable names per environment (secret names
only — safe to commit); `~/.config/secretov/projects.yaml` maps project names
to roots so `-p` works from anywhere. A manifest can also carry a `vars:`
block of plaintext non-secret config (log levels, public URLs) that `exec`
injects without touching the store — committed as-is, so never put a secret
there. Manifest schema is in [DESIGN.md](DESIGN.md).

```sh
cd ~/src/myproj
secretov import -p myproj -e dev          # .env -> dev/myproj/*, writes .secretov.yaml
secretov exec -e dev -- npm run dev       # inject that env's secrets
secretov exec -e dev --dry-run            # show VAR <- key, no values
secretov list -p myproj -e dev
printf 'new-pw' | secretov set DB_URL -e dev   # replaces dev/myproj/DB_URL
```

`-e` falls back to `$SECRETOV_ENV`, then the manifest's `default_env`.

Two steps `import` does **not** do, and both are easy to miss:

1. **Register the project** — add it to `~/.config/secretov/projects.yaml`, or
   `-p NAME` fails anywhere outside the project directory.
2. **Set `default_env`** — add it to the manifest, or every later command needs
   an explicit `-e`.

```yaml
# ~/.config/secretov/projects.yaml
projects:
  myproj:
    root: "${HOME}/src/myproj"
```

## Backup and recovery

There is no recovery path inside secretov: the store is one encrypted file
and the passphrase is the only key. Two things must survive independently:

1. **The passphrase** — keep it in your password manager. Without it a backup
   is noise.
2. **The store file** — `~/.local/share/secretov/store` (`$XDG_DATA_HOME`).
   It is ciphertext (secretbox + Argon2id), safe to copy anywhere, including
   cloud sync or a git repo of dotfiles.

Also worth copying, though both are regenerable:
`~/.config/secretov/token` (rewrite with 64 hex chars from
`/dev/urandom` if lost — the daemon reads it at start) and
`~/.config/secretov/projects.yaml` (registry; hand-editable).
`.secretov.yaml` manifests live in their repos and contain no values.

Writes are atomic (temp file + fsync + rename), so a plain copy at any moment
is a consistent snapshot:

```sh
cp ~/.local/share/secretov/store  ~/backups/secretov-store-$(date +%F)
cp ~/.config/secretov/token       ~/backups/secretov-token
```

A backup is decryptable only with the passphrase that was current when it was
taken — after `secretov passwd`, take a fresh backup and retire old ones.

**Verify a backup** without touching the live store, using overridden XDG
dirs (this machine exports them globally, so override all three):

```sh
T=$(mktemp -d) && mkdir -p $T/data/secretov $T/config/secretov $T/run
cp ~/backups/secretov-store-2026-08-30 $T/data/secretov/store
cp ~/backups/secretov-token           $T/config/secretov/token
export XDG_DATA_HOME=$T/data XDG_CONFIG_HOME=$T/config XDG_RUNTIME_DIR=$T/run
secretov daemon &            # prompts for the passphrase
secretov list                # keys appear -> backup is good
kill %1; rm -rf $T; unset XDG_DATA_HOME XDG_CONFIG_HOME XDG_RUNTIME_DIR
```

**Restore**: stop the daemon (`scripts/service stop`), copy the store (and
token) back to their paths, `scripts/service start`.

## Running as a service

`scripts/service` manages the daemon as a local service (platform-agnostic
dispatcher; Linux/systemd implemented, macOS/launchd not yet). The passphrase
is kept in the session keyring (`secret-tool`, package `libsecret-tools`) so
the daemon starts at login without a prompt; see SECURITY.md finding 10 for
what that trades away.

```sh
scripts/service install      # build + install binary to ~/.local/bin, register + enable user unit
scripts/service start        # stores the passphrase in the keyring on first use, then starts
scripts/service passphrase   # replace the keyring copy (after `secretov passwd`)
scripts/service stop
scripts/service status
scripts/service update       # rebuild + reinstall, restart daemon if running
```
