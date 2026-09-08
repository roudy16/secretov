#include "daemon.hpp"

#include <poll.h>
#include <signal.h>
#include <sodium.h>
#include <sys/prctl.h>
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

// UnixSocketListener::accept() swallows EINTR, so a signal can't unwind the
// accept loop. We unlink the socket and _exit from the handler instead.
// No clean stack unwind on shutdown; OS reclaims the mlock'd key.
char g_socket_path[512] = {};

void on_signal(int) {
    if (g_socket_path[0] != '\0') {
        ::unlink(g_socket_path);
    }
    ::_exit(0);
}

bool token_matches(const std::string& expected, const std::string& got) {
    if (expected.size() != got.size()) return false;
    return sodium_memcmp(expected.data(), got.data(), expected.size()) == 0;
}

std::string dispatch(Store& store, const Request& req, std::uint64_t now) {
    if (req.op == "get") {
        if (req.key.empty()) return error_response("missing key");
        auto value = store.get(req.key);
        if (!value) return error_response("not found");
        return ok_value(*value);
    }
    if (req.op == "set") {
        if (req.key.empty()) return error_response("missing key");
        store.set(req.key, req.value);
        return ok_response();
    }
    if (req.op == "delete") {
        if (req.key.empty()) return error_response("missing key");
        if (!store.remove(req.key)) return error_response("not found");
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
        store.change_passphrase(req.old_pass, req.new_pass);
        return ok_response();
    }
    return error_response("unknown op: " + req.op);
}

void serve_connection(Connection& conn, Store& store, const std::string& expected_token) {
    if (conn.peer_uid() != ::getuid()) {
        conn.write_line(error_response("permission denied: peer uid mismatch"));
        return;
    }
    while (auto line = conn.read_line()) {
        auto req = parse_request(*line);
        if (!req) {
            conn.write_line(error_response("malformed request"));
            continue;
        }
        if (!token_matches(expected_token, req->token)) {
            conn.write_line(error_response("invalid token"));
            continue;
        }
        std::string response;
        try {
            response = dispatch(store, *req, static_cast<std::uint64_t>(std::time(nullptr)));
        } catch (const std::exception& e) {
            std::cerr << "secretov: error handling '" << req->op << "': " << e.what() << "\n";
            response = error_response(e.what());
        }
        if (!conn.write_line(response)) {
            return;  // peer went away mid-write; drop the connection
        }
    }
}

}  // namespace

int run_daemon() {
    // A secrets daemon must never be dumpable: a core would spill the key/passphrase.
    struct rlimit no_core{0, 0};
    if (::setrlimit(RLIMIT_CORE, &no_core) != 0) {
        throw std::runtime_error("setrlimit(RLIMIT_CORE) failed: " +
                                 std::string(std::strerror(errno)));
    }
    if (::prctl(PR_SET_DUMPABLE, 0) != 0) {
        throw std::runtime_error("prctl(PR_SET_DUMPABLE) failed: " +
                                 std::string(std::strerror(errno)));
    }

    Paths paths = resolve_paths();

    std::string passphrase;
    try {
        passphrase = read_passphrase("Passphrase: ");
    } catch (const std::exception& e) {
        std::cerr << "secretov: " << e.what() << "\n";
        return 1;
    }

    std::uint64_t now = static_cast<std::uint64_t>(std::time(nullptr));
    Store store = [&] {
        try {
            return Store::open(paths.store, passphrase);
        } catch (const std::exception& e) {
            std::cerr << "secretov: cannot open store: " << e.what() << "\n"
                      << "  (run 'secretov init' first, or check your passphrase)\n";
            std::exit(1);
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
            std::cerr << "secretov: auto-rotation failed: " << e.what() << "\n";
            return 1;
        }
    }

    // The store retains only the data key from here on; the passphrase and
    // the wrapping key derived from it are never held past unlock.
    sodium_memzero(passphrase.data(), passphrase.size());
    passphrase.clear();

    std::string expected_token;
    try {
        expected_token = rstrip(read_file_string(paths.token));
    } catch (const std::exception& e) {
        std::cerr << "secretov: cannot read token file '" << paths.token << "': " << e.what()
                  << "\n  (run 'secretov init' first)\n";
        return 1;
    }
    if (expected_token.empty()) {
        std::cerr << "secretov: token file '" << paths.token << "' is empty\n";
        return 1;
    }

    if (paths.socket.size() >= sizeof(g_socket_path)) {
        std::cerr << "secretov: socket path too long: " << paths.socket << "\n";
        return 1;
    }
    std::strncpy(g_socket_path, paths.socket.c_str(), sizeof(g_socket_path) - 1);

    struct sigaction sa{};
    sa.sa_handler = on_signal;
    ::sigemptyset(&sa.sa_mask);
    ::sigaction(SIGINT, &sa, nullptr);
    ::sigaction(SIGTERM, &sa, nullptr);
    ::signal(SIGPIPE, SIG_IGN);

    UnixSocketListener listener(paths.socket);
    std::cerr << "secretov: listening on " << paths.socket << " (store " << paths.store << ")\n";

    for (;;) {
        std::unique_ptr<Connection> conn = listener.accept();
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
