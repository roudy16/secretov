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
printf 'hunter2' | just run set DB_PASS
just run get DB_PASS
just run exec --secret DB_PASS -- your-command   # inject into child env
just run tui                       # interactive terminal UI
```

Commands: `init`, `daemon`, `get`, `set` (value via stdin only), `list`,
`delete`, `rotate`, `passwd` (change store passphrase; daemon must be
running), `exec`, `import`, `tui`.

## Projects and environments

Scoped secrets are keyed `env/project/KEY`. A `.secretov.yaml` at a project
root maps secrets to environment variable names per environment (names only —
safe to commit); `~/.config/secretov/projects.yaml` maps project names to
roots so `-p` works from anywhere. Details and the manifest schema are in
[DESIGN.md](DESIGN.md).

```sh
cd ~/src/myproj
secretov import -p myproj -e dev          # .env -> dev/myproj/*, writes .secretov.yaml
secretov exec -e dev -- npm run dev       # inject that env's secrets
secretov exec -e dev --dry-run            # show VAR <- key, no values
secretov list -p myproj -e dev
```

`-e` falls back to `$SECRETOV_ENV`, then the manifest's `default_env`.

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
dispatcher; Linux/systemd implemented, macOS/launchd not yet):

```sh
scripts/service install   # build + install binary to ~/.local/bin, register user unit
scripts/service start     # prompts for passphrase (no auto-start at boot — it needs one)
scripts/service stop
scripts/service status
scripts/service update    # rebuild + reinstall, restart daemon if running
```
