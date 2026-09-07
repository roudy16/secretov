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
        << "  set KEY [-p NAME] [-e ENV] set a secret, creating or replacing it\n"
        << "                             (value read from stdin; -p/-e scope the key)\n"
        << "  list [-p NAME] [-e ENV]    list secret names (optionally one env/project scope)\n"
        << "  delete KEY                 remove a secret\n"
        << "  rotate                     re-encrypt the store with a fresh key\n"
        << "  passwd                     change the store passphrase\n"
        << "  tui                        interactive terminal UI\n"
        << "  exec [-p NAME] [-e ENV] [--dry-run] [--secret KEY[=ENVVAR]]... -- PROG [ARGS...]\n"
        << "                             inject the project manifest's secrets (and any\n"
        << "                             --secret raw keys) into env and run PROG\n"
        << "  import [FILE] [-p NAME] [-e ENV] [--overwrite]\n"
        << "                             import a dotenv file (default .env) into env/project/*\n"
        << "                             and record the mapping in the project manifest\n";
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
        if (cmd == "list") return cmd_list(argc - 2, argv + 2);
        if (cmd == "import") return cmd_import(argc - 2, argv + 2);
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
        if (cmd == "set") return cmd_set(argc - 2, argv + 2);
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
