#include "daemon.hpp"

#include <poll.h>
#include <signal.h>
#include <sodium.h>
#include <sys/resource.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <ctime>
#include <iostream>
#include <stdexcept>
#include <string>

#include "paths.hpp"
#include "protocol.hpp"
#include "store.hpp"
#include "transport.hpp"

namespace secretov {

namespace {

constexpr int kRotateAfterDays = 30;  // fixed 30d, make a flag if anyone asks

// Listener::accept() swallows EINTR, so a signal can't unwind the
// accept loop. We unlink the socket and _exit from the handler instead.
// No clean stack unwind on shutdown; OS reclaims the mlock'd key.
// Set before the handler is installed, so the handler never sees them torn.
char g_socket_path[512] = {};
dev_t g_socket_dev = 0;
ino_t g_socket_ino = 0;

void on_signal(int) {
    // Another daemon may have replaced the path since we bound it; leave theirs.
    unlink_if_same_inode(g_socket_path, g_socket_dev, g_socket_ino);
    ::_exit(0);
}

class WipeOnExit {
public:
    explicit WipeOnExit(std::string& text) : text_(text) {}
    ~WipeOnExit() { wipe(text_); }
    WipeOnExit(const WipeOnExit&) = delete;
    WipeOnExit& operator=(const WipeOnExit&) = delete;

private:
    std::string& text_;
};

bool token_matches(const std::string& expected, const std::string& got) {
    if (expected.size() != got.size()) return false;
    return sodium_memcmp(expected.data(), got.data(), expected.size()) == 0;
}

std::string dispatch(Store& store, const Request& req, std::uint64_t now) {
    if (req.op == "get") {
        if (req.key.empty()) return error_response("missing key");
        auto value = store.get(req.key);
        if (!value) return error_response(kErrNotFound);
        return ok_value(*value);
    }
    if (req.op == "set") {
        if (req.key.empty()) return error_response("missing key");
        store.set(req.key, req.value);
        return ok_response();
    }
    if (req.op == "delete") {
        if (req.key.empty()) return error_response("missing key");
        if (!store.remove(req.key)) return error_response(kErrNotFound);
        return ok_response();
    }
    if (req.op == "list") {
        return ok_keys(store.list());
    }
    if (req.op == "getprefix") {
        if (req.key.empty()) return error_response("missing prefix");
        return ok_values(store.get_prefix(req.key));
    }
    if (req.op == "rotate") {
        if (req.old_pass.empty()) return error_response("missing passphrase");
        store.rotate(req.old_pass, now);
        return ok_response();
    }
    if (req.op == "passwd") {
        if (req.old_pass.empty() || req.new_pass.empty()) return error_response("missing passphrase");
        store.change_passphrase(req.old_pass, req.new_pass, now);
        return ok_response();
    }
    return error_response("unknown op: " + req.op);
}

void serve_connection(Connection& conn, Store& store, const std::string& expected_token) {
    if (conn.peer_uid() != ::getuid()) {
        conn.write_line(error_response("permission denied: peer uid mismatch"));
        return;
    }
    while (auto line = conn.read_line(kMaxRequestBytes)) {
        // ponytail: nlohmann::json's parse tree holds its own copies of the
        // passphrase/value strings and frees them unscrubbed; scrubbing those
        // needs a custom allocator or a hand-rolled parser.
        auto req = parse_request(*line);
        wipe(*line);
        if (!req) {
            conn.write_line(error_response("malformed request"));
            continue;
        }
        std::string response;
        if (!token_matches(expected_token, req->token)) {
            response = error_response(kErrInvalidToken);
        } else {
            try {
                response = dispatch(store, *req, static_cast<std::uint64_t>(std::time(nullptr)));
            } catch (const std::exception& e) {
                std::cerr << "secretov: error handling '" << req->op << "': " << e.what() << "\n";
                response = error_response(e.what());
            }
        }
        wipe(req->old_pass);
        wipe(req->new_pass);
        wipe(req->value);
        if (!conn.write_line(response)) {
            return;  // peer went away mid-write; drop the connection
        }
    }
}

}  // namespace

int run_daemon() {
    // main() already cleared PR_SET_DUMPABLE; a zero core limit also covers
    // a dump requested after something re-enables it.
    struct rlimit no_core{0, 0};
    if (::setrlimit(RLIMIT_CORE, &no_core) != 0) {
        throw std::runtime_error("setrlimit(RLIMIT_CORE) failed: " +
                                 std::string(std::strerror(errno)));
    }

    Paths paths = resolve_paths();

    // Fail before the passphrase prompt (and any auto-rotate, which would
    // re-key the store under the running daemon). Listener re-checks at bind.
    if (connect_unix(paths.socket)) {
        throw std::runtime_error("daemon already running at " + paths.socket);
    }

    std::string passphrase = read_passphrase("Passphrase: ");
    WipeOnExit wipe_passphrase_on_exit(passphrase);

    std::uint64_t now = static_cast<std::uint64_t>(std::time(nullptr));
    Store store = [&] {
        try {
            return Store::open(paths.store, passphrase);
        } catch (const std::exception& e) {
            throw std::runtime_error(std::string("cannot open store: ") + e.what() +
                                     "\n  (run 'secretov init' first, or check your passphrase)");
        }
    }();

    const std::uint64_t rotate_after = static_cast<std::uint64_t>(kRotateAfterDays) * 24 * 3600;
    if (now > store.key_created_at() && now - store.key_created_at() > rotate_after) {
        try {
            // The passphrase is still in hand at this point in startup.
            store.rotate(passphrase, now);
            std::cerr << "secretov: key older than " << kRotateAfterDays
                      << " days; rotated on unlock\n";
        } catch (const std::exception& e) {
            throw std::runtime_error(std::string("auto-rotation failed: ") + e.what());
        }
    }

    // The store retains only the data key from here on; the passphrase and
    // the wrapping key derived from it are never held past unlock.
    wipe(passphrase);

    std::string expected_token;
    try {
        expected_token = rstrip(read_file_string(paths.token));
    } catch (const std::exception& e) {
        throw std::runtime_error("cannot read token file '" + paths.token + "': " + e.what() +
                                 "\n  (run 'secretov init' first)");
    }
    if (expected_token.empty()) {
        throw std::runtime_error("token file '" + paths.token + "' is empty");
    }

    Listener listener(paths.socket);
    // Listener refuses a path longer than sun_path, so it fits.
    std::strncpy(g_socket_path, paths.socket.c_str(), sizeof(g_socket_path) - 1);
    g_socket_dev = listener.bound_dev();
    g_socket_ino = listener.bound_ino();

    // Installed only after the globals above are final. A signal in the gap
    // takes the default action and leaves a stale socket, which the next
    // start removes.
    struct sigaction sa{};
    sa.sa_handler = on_signal;
    ::sigemptyset(&sa.sa_mask);
    ::sigaction(SIGINT, &sa, nullptr);
    ::sigaction(SIGTERM, &sa, nullptr);
    ::signal(SIGPIPE, SIG_IGN);
    std::cerr << "secretov: listening on " << paths.socket << " (store " << paths.store << ")\n";

    for (;;) {
        std::optional<Connection> conn = listener.accept();
        if (!conn) {
            ::poll(nullptr, 0, 100);  // back off; avoid busy-spin on persistent accept errors (EMFILE)
            continue;  // one connection at a time; threads when a real client blocks another
        }
        try {
            serve_connection(*conn, store, expected_token);
        } catch (const std::exception& e) {
            std::cerr << "secretov: connection error: " << e.what() << "\n";
        }
    }
}

}  // namespace secretov
