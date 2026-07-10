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
`delete`, `rotate`, `exec`, `tui`.
