#pragma once

namespace secretov {

// Run the secretov daemon in the foreground. Reads the passphrase, opens the
// store, serves requests on the unix socket until SIGINT/SIGTERM. Returns a
// process exit code.
int run_daemon();

}  // namespace secretov
