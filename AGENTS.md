# secretov — agent notes

Local secrets service: daemon + CLI + TUI in one C++20 binary. Read DESIGN.md
first — it is the authoritative spec (threat model, protocol, file format,
accepted security ceilings). Don't re-litigate decisions recorded there.

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
- `src/transport.{hpp,cpp}` — Listener/Connection interface + unix socket
  impl. New transports implement the interface; don't touch service logic.
- `src/client.{hpp,cpp}`, `src/tui.cpp`, `src/paths.hpp`, `src/protocol.hpp`.
- `tests/store_test.cpp` (assert-based, no framework), `tests/smoke_test.sh`
  (full daemon lifecycle in a scratch env).

## Constraints

- Dependencies: libsodium, nlohmann/json, FTXUI. Nothing else without a
  fight. System packages are preferred when present; fallback is vendored
  (`third_party/get-deps.sh`, no sudo needed) and FetchContent for FTXUI.
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
