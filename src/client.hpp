#pragma once

#include <optional>
#include <string>

namespace secretov {

// Each returns a process exit code. Paths are resolved from the environment.
int cmd_init();
int cmd_get(const std::string& key);
int cmd_set(const std::string& key);  // value is read from stdin
int cmd_list(int argc, char** argv);    // [-p NAME] [-e ENV]
int cmd_delete(const std::string& key);
int cmd_rotate();
int cmd_passwd();  // reads current + new passphrase from tty/stdin
int cmd_exec(int argc, char** argv);    // argv/argc positioned at args after "exec"
int cmd_import(int argc, char** argv);  // [FILE] [-p NAME] [-e ENV] [--overwrite]

}  // namespace secretov
