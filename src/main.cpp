#include <exception>
#include <iostream>
#include <string>

#include "client.hpp"
#include "daemon.hpp"
#include "tui.hpp"

namespace {

void print_usage(std::ostream& out) {
    out << "usage: secretov <command> [args...]\n"
        << "commands:\n"
        << "  init                       create the store and mint an API token\n"
        << "  daemon                     run the secrets daemon (foreground)\n"
        << "  get KEY                    print a secret's value\n"
        << "  set KEY                    set a secret (value read from stdin)\n"
        << "  list                       list secret names\n"
        << "  delete KEY                 remove a secret\n"
        << "  rotate                     re-encrypt the store with a fresh key\n"
        << "  passwd                     change the store passphrase\n"
        << "  tui                        interactive terminal UI\n"
        << "  exec [--secret NAME[=ENVVAR]]... -- PROG [ARGS...]\n"
        << "                             inject secrets into env and run PROG\n";
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage(std::cerr);
        return 2;
    }

    std::string cmd = argv[1];
    if (cmd == "--help" || cmd == "-h") {
        print_usage(std::cout);
        return 0;
    }

    using namespace secretov;

    try {
        if (cmd == "init") return cmd_init();
        if (cmd == "daemon") return run_daemon();
        if (cmd == "list") return cmd_list();
        if (cmd == "rotate") return cmd_rotate();
        if (cmd == "passwd") return cmd_passwd();
        if (cmd == "tui") return run_tui();

        if (cmd == "get") {
            if (argc < 3) {
                std::cerr << "usage: secretov get KEY\n";
                return 2;
            }
            return cmd_get(argv[2]);
        }
        if (cmd == "set") {
            // Value comes from stdin only; an argv VALUE would leak via /proc/<pid>/cmdline.
            if (argc != 3) {
                std::cerr << "usage: secretov set KEY   (value read from stdin)\n";
                return 2;
            }
            return cmd_set(argv[2]);
        }
        if (cmd == "delete") {
            if (argc < 3) {
                std::cerr << "usage: secretov delete KEY\n";
                return 2;
            }
            return cmd_delete(argv[2]);
        }
        if (cmd == "exec") {
            return cmd_exec(argc - 2, argv + 2);
        }
    } catch (const std::exception& e) {
        std::cerr << "secretov: " << e.what() << "\n";
        return 1;
    }

    print_usage(std::cerr);
    return 2;
}
