#include "client.hpp"

#include <sodium.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "paths.hpp"
#include "protocol.hpp"
#include "store.hpp"
#include "transport.hpp"

namespace secretov {

namespace {

// Read whole stdin, strip a single trailing newline. Keeps secrets out of argv.
std::string read_stdin_value() {
    std::stringstream ss;
    ss << std::cin.rdbuf();
    std::string value = ss.str();
    if (!value.empty() && value.back() == '\n') value.pop_back();
    if (!value.empty() && value.back() == '\r') value.pop_back();
    return value;
}

std::string load_token(const Paths& paths) {
    std::string token = rstrip(read_file_string(paths.token));
    if (token.empty()) {
        throw std::runtime_error("token file '" + paths.token + "' is empty");
    }
    return token;
}

// Connect, send one request, return the parsed response. Throws on I/O trouble.
nlohmann::json send_request(const Paths& paths, const std::string& token, const std::string& op,
                            const std::string& key, const std::optional<std::string>& value) {
    std::unique_ptr<Connection> conn = connect_unix(paths.socket);
    if (!conn) {
        throw std::runtime_error("daemon not running at " + paths.socket + " ?");
    }
    nlohmann::json req{{"token", token}, {"op", op}};
    if (!key.empty()) req["key"] = key;
    if (value) req["value"] = *value;

    if (!conn->write_line(req.dump())) {
        throw std::runtime_error("failed to send request to daemon");
    }
    auto line = conn->read_line();
    if (!line) {
        throw std::runtime_error("daemon closed connection without responding");
    }
    nlohmann::json resp;
    try {
        resp = nlohmann::json::parse(*line);
    } catch (const nlohmann::json::exception&) {
        throw std::runtime_error("malformed response from daemon");
    }
    return resp;
}

// Send a request and, on a non-ok response, throw its error message.
nlohmann::json request_or_throw(const Paths& paths, const std::string& token, const std::string& op,
                                const std::string& key, const std::optional<std::string>& value) {
    nlohmann::json resp = send_request(paths, token, op, key, value);
    if (!resp.value("ok", false)) {
        throw std::runtime_error(resp.value("error", std::string("request failed")));
    }
    return resp;
}

}  // namespace

int cmd_init() {
    Paths paths = resolve_paths();
    try {
        std::string passphrase = read_passphrase("Passphrase: ");
        if (::isatty(STDIN_FILENO)) {
            std::string confirm = read_passphrase("Confirm passphrase: ");
            if (passphrase != confirm) {
                std::cerr << "secretov: passphrases do not match\n";
                return 1;
            }
        }

        ensure_parent_dir(paths.store);
        Store::create(paths.store, passphrase, static_cast<std::uint64_t>(std::time(nullptr)));

        unsigned char raw[32];
        randombytes_buf(raw, sizeof(raw));
        char hex[sizeof(raw) * 2 + 1];
        sodium_bin2hex(hex, sizeof(hex), raw, sizeof(raw));
        sodium_memzero(raw, sizeof(raw));
        write_file_atomic(paths.token, hex, 0600);
        sodium_memzero(hex, sizeof(hex));
    } catch (const std::exception& e) {
        std::cerr << "secretov: init failed: " << e.what() << "\n";
        return 1;
    }
    std::cout << "secretov initialized\n"
              << "  store: " << paths.store << "\n"
              << "  token: " << paths.token << "\n"
              << "  socket: " << paths.socket << "\n"
              << "Start the daemon with: secretov daemon\n";
    return 0;
}

int cmd_get(const std::string& key) {
    Paths paths = resolve_paths();
    try {
        nlohmann::json resp = request_or_throw(paths, load_token(paths), "get", key, std::nullopt);
        std::cout << resp.value("value", std::string{}) << "\n";
    } catch (const std::exception& e) {
        std::cerr << "secretov: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

int cmd_set(const std::string& key) {
    Paths paths = resolve_paths();
    try {
        std::string token = load_token(paths);
        request_or_throw(paths, token, "set", key, read_stdin_value());
    } catch (const std::exception& e) {
        std::cerr << "secretov: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

int cmd_list() {
    Paths paths = resolve_paths();
    try {
        nlohmann::json resp = request_or_throw(paths, load_token(paths), "list", "", std::nullopt);
        for (const auto& key : resp.value("keys", std::vector<std::string>{})) {
            std::cout << key << "\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "secretov: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

int cmd_delete(const std::string& key) {
    Paths paths = resolve_paths();
    try {
        request_or_throw(paths, load_token(paths), "delete", key, std::nullopt);
    } catch (const std::exception& e) {
        std::cerr << "secretov: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

int cmd_rotate() {
    Paths paths = resolve_paths();
    try {
        request_or_throw(paths, load_token(paths), "rotate", "", std::nullopt);
    } catch (const std::exception& e) {
        std::cerr << "secretov: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

int cmd_exec(int argc, char** argv) {
    std::vector<std::pair<std::string, std::string>> secrets;  // (name, envvar)
    int i = 0;
    for (; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--") {
            ++i;
            break;
        }
        if (arg == "--secret") {
            if (i + 1 >= argc) {
                std::cerr << "secretov exec: --secret requires NAME[=ENVVAR]\n";
                return 2;
            }
            std::string spec = argv[++i];
            std::size_t eq = spec.find('=');
            if (eq == std::string::npos) {
                secrets.emplace_back(spec, spec);
            } else {
                secrets.emplace_back(spec.substr(0, eq), spec.substr(eq + 1));
            }
        } else {
            std::cerr << "secretov exec: unexpected argument '" << arg << "' before '--'\n";
            return 2;
        }
    }

    if (i >= argc) {
        std::cerr << "usage: secretov exec [--secret NAME[=ENVVAR]]... -- PROG [ARGS...]\n";
        return 2;
    }

    Paths paths = resolve_paths();
    try {
        std::string token = load_token(paths);
        for (const auto& [name, envvar] : secrets) {
            nlohmann::json resp = request_or_throw(paths, token, "get", name, std::nullopt);
            std::string value = resp.value("value", std::string{});
            if (::setenv(envvar.c_str(), value.c_str(), 1) != 0) {
                throw std::runtime_error("setenv '" + envvar + "' failed");
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "secretov exec: " << e.what() << "\n";
        return 1;
    }

    ::execvp(argv[i], &argv[i]);
    std::cerr << "secretov exec: cannot run '" << argv[i] << "': " << std::strerror(errno) << "\n";
    return 1;
}

}  // namespace secretov
