# secretov — agent notes

Local secrets service: daemon + CLI + TUI in one C++20 binary. Read DESIGN.md
first — it is the authoritative spec (threat model, protocol, file format,
accepted security ceilings). Don't re-litigate decisions recorded there.

This file is for working *on* secretov. USING.md is the consumer guide, for
humans and agents using secretov from another project — any change to the CLI
surface, scope resolution, or manifest/registry format must update it.

## Workflows

All through `just`: `setup` (fetches vendored deps, configures), `build`,
`test`, `run [args...]`, `install`, `clean`. Tests must pass and the build
must stay zero-warning under `-Wall -Wextra` before any work is done.

## Layout

- `src/main.cpp` — subcommand dispatch; top-level try/catch is the only
  place exceptions become exit codes.
- `src/store.{hpp,cpp}` — encrypted store (libsodium secretbox, Argon2id).
  File format documented in store.hpp. Security-critical: review-level care.
- `src/daemon.{hpp,cpp}` — request loop, peer-UID + constant-time token
  checks, auto-rotation. Security-critical.
- `src/transport.{hpp,cpp}` — unix socket Connection/Listener classes.
- `src/manifest.{hpp,cpp}` — `.secretov.yaml` manifests, `projects.yaml`
  registry, dotenv parsing, and the comment-preserving text insertion that
  `import` uses to update manifests (re-parsed and verified before writing).
- `src/client.{hpp,cpp}` (scope resolution for exec/import/list lives here),
  `src/tui.cpp`, `src/paths.hpp` (all on-disk file names as constants —
  single source of truth), `src/protocol.hpp`.
- `tests/store_test.cpp`, `tests/manifest_test.cpp` (assert-based, no
  framework), `tests/smoke_test.sh` (full daemon lifecycle + scopes in a
  scratch env).
- `scripts/service` + `scripts/linux-systemd.sh` — run the daemon as a
  systemd user unit started at login, passphrase from the session keyring
  via `secret-tool`; SECURITY.md is the security worklist.

## Constraints

- Dependencies: libsodium, nlohmann/json, FTXUI, yaml-cpp. Nothing else
  without a fight. System packages are preferred when present; fallback is
  vendored (`third_party/get-deps.sh`, sha256-verified, no sudo needed) and
  FetchContent pinned by commit hash for FTXUI and yaml-cpp. Bumping any of
  them means updating its digest/hash in the same change.
- Manifest edits must never reformat the user's YAML or drop comments —
  text-level insertion only (see `manifest_with_entries`).
- Secrets never go in argv (`/proc/<pid>/cmdline` is world-readable) — this
  is why `set` reads stdin only. Preserve that property in new code.
- Key/passphrase buffers: mlock + `sodium_memzero` on the daemon side;
  best-effort zeroing elsewhere (ceilings documented in code comments).
- Errors: explicit everywhere, thrown with context; no silent failures.

## Gotchas

- FTXUI's CMake defaults the build to Release (`-DNDEBUG`). store_test.cpp
  has `#undef NDEBUG` so its asserts survive — keep that in any new
  assert-based test file.
- Scratch-testing the binary: this machine exports `XDG_DATA_HOME`/
  `XDG_CONFIG_HOME` globally, so override `XDG_DATA_HOME`, `XDG_CONFIG_HOME`,
  and `XDG_RUNTIME_DIR` (not just `HOME`) or you will write into the real
  `~/.local/share/secretov`.
- Daemon passphrase is read from stdin when not a tty — pipe it for scripts.
- TUI can't be tested headless; drive it with tmux (`send-keys`,
  `capture-pane`). `secretov tui < /dev/null` must keep failing cleanly.
- `compile_commands.json` needs project-scope `CMAKE_EXPORT_COMPILE_COMMANDS`
  (already set); without it only FTXUI's TUs export and clangd reports
  phantom include errors.
