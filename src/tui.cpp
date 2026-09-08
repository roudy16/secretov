#include "tui.hpp"

#include <sodium.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <ftxui/component/component.hpp>
#include <ftxui/component/component_options.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <nlohmann/json.hpp>

#include "client.hpp"
#include "paths.hpp"
#include "protocol.hpp"

// Secret hygiene ceiling: revealed values and the add-form value buffer are
// zeroed (sodium_memzero) as soon as they are re-masked/submitted/cancelled.
// FTXUI copies buffer contents into its own render structures each frame; those
// copies are not zeroed. Best-effort — good enough for a local TUI, not a
// hardened enclave. Upgrade path: a custom no-copy render element if it matters.

namespace secretov {

namespace {

using nlohmann::json;

void zero(std::string& s) {
    if (!s.empty()) sodium_memzero(s.data(), s.size());
    s.clear();
}

enum class Mode { Normal, Add, Edit, ConfirmDelete, ConfirmRotate };

int run_ui(DaemonClient& daemon) {
    using namespace ftxui;

    std::vector<std::string> keys;
    int selected = 0;
    std::optional<std::string> revealed;  // fetched value for the selected key
    std::string add_name;
    std::string add_value;
    std::string status = "ready";
    Mode mode = Mode::Normal;
    int active_tab = 0;  // 0 = key list, 1 = add/edit form
    int form_field = 0;  // 0 = name input, 1 = value input

    auto remask = [&] {
        if (revealed) {
            zero(*revealed);
            revealed.reset();
        }
    };

    auto refresh = [&](const std::string& select_key) {
        remask();
        try {
            json resp = daemon.request("list");
            keys = resp.value("keys", std::vector<std::string>{});
        } catch (const std::exception& e) {
            status = e.what();
            return;
        }
        std::sort(keys.begin(), keys.end());
        if (!select_key.empty()) {
            auto it = std::find(keys.begin(), keys.end(), select_key);
            if (it != keys.end()) selected = static_cast<int>(it - keys.begin());
        }
        if (selected >= static_cast<int>(keys.size())) selected = static_cast<int>(keys.size()) - 1;
        if (selected < 0) selected = 0;
    };

    auto reveal = [&] {
        if (keys.empty()) {
            status = "no secret to reveal";
            return;
        }
        try {
            json resp = daemon.request("get", keys[static_cast<std::size_t>(selected)],
                                       std::nullopt);
            remask();
            revealed = resp.value("value", std::string{});
            status = "revealed " + keys[static_cast<std::size_t>(selected)];
        } catch (const std::exception& e) {
            status = e.what();
        }
    };

    auto start_add = [&] {
        zero(add_name);
        zero(add_value);
        mode = Mode::Add;
        active_tab = 1;
        form_field = 0;
        status = "adding secret";
    };

    // Edit reuses the add form's value buffer; the key is fixed to the
    // selection and the old value is never fetched into the input (a blank
    // field is one fewer plaintext copy, and 'r' already reveals on demand).
    auto start_edit = [&] {
        if (keys.empty()) {
            status = "no secret to edit";
            return;
        }
        remask();
        zero(add_value);
        mode = Mode::Edit;
        active_tab = 1;
        form_field = 1;
        status = "editing " + keys[static_cast<std::size_t>(selected)];
    };

    auto cancel_form = [&] {
        zero(add_name);
        zero(add_value);
        mode = Mode::Normal;
        active_tab = 0;
        form_field = 0;
        status = "cancelled";
    };

    auto submit_add = [&] {
        if (add_name.empty()) {
            status = "name required";
            return;
        }
        std::string name = add_name;
        try {
            daemon.request("set", name, add_value);
            status = "added " + name;
            zero(add_name);
            zero(add_value);
            mode = Mode::Normal;
            active_tab = 0;
            refresh(name);
        } catch (const std::exception& e) {
            status = e.what();
        }
    };

    auto submit_edit = [&] {
        if (add_value.empty()) {
            status = "value required";
            return;
        }
        std::string key = keys[static_cast<std::size_t>(selected)];
        try {
            daemon.request("set", key, add_value);
            status = "updated " + key;
            zero(add_value);
            mode = Mode::Normal;
            active_tab = 0;
            form_field = 0;
            refresh(key);
        } catch (const std::exception& e) {
            status = e.what();
        }
    };

    auto do_delete = [&] {
        std::string key = keys[static_cast<std::size_t>(selected)];
        try {
            daemon.request("delete", key, std::nullopt);
            status = "deleted " + key;
            refresh("");
        } catch (const std::exception& e) {
            status = e.what();
        }
        mode = Mode::Normal;
    };

    auto do_rotate = [&] {
        try {
            daemon.request("rotate");
            status = "rotated encryption key";
        } catch (const std::exception& e) {
            status = e.what();
        }
        mode = Mode::Normal;
    };

    refresh("");

    MenuOption menu_opt = MenuOption::Vertical();
    menu_opt.on_change = remask;
    Component menu = Menu(&keys, &selected, menu_opt);

    Component name_input = Input(&add_name, "name");
    InputOption value_opt;
    value_opt.password = true;
    Component value_input = Input(&add_value, "value", value_opt);
    Component form = Container::Vertical({name_input, value_input}, &form_field);

    Component tab = Container::Tab({menu, form}, &active_tab);

    auto renderer = Renderer(tab, [&] {
        Element list_pane = window(text(" secrets "),
                                   keys.empty()
                                       ? (text("(empty)") | dim | center)
                                       : (menu->Render() | vscroll_indicator | frame)) |
                            size(WIDTH, EQUAL, 30);

        Element detail_body;
        if (keys.empty()) {
            detail_body = text("press 'a' to add a secret") | dim | center;
        } else {
            Element value_line = revealed ? text(*revealed) : text("••••••••");
            detail_body = vbox({
                hbox({text("name:  "), text(keys[static_cast<std::size_t>(selected)]) | bold}),
                separator(),
                hbox({text("value: "), value_line}),
                text(revealed ? "" : "(press 'r' to reveal)") | dim,
            });
        }
        Element detail_pane = window(text(" detail "), detail_body) | flex;

        Element hints =
            text(" a add   e edit   d delete   R rotate   r reveal   h hide   q quit ") | dim |
            center;
        Element status_bar =
            hbox({
                text(" " + daemon.socket_path() + " "),
                separator(),
                text(" keys: " + std::to_string(keys.size()) + " "),
                separator(),
                text(" " + status + " ") | flex,
            }) |
            inverted;

        Element root = vbox({
            hbox({list_pane, detail_pane}) | flex,
            hints,
            status_bar,
        });

        if (mode == Mode::Add) {
            Element overlay = window(text(" add secret "),
                                     vbox({
                                         hbox({text("name:  "), name_input->Render()}),
                                         hbox({text("value: "), value_input->Render()}),
                                         separator(),
                                         text("Enter submit   Esc cancel") | dim,
                                     })) |
                              size(WIDTH, GREATER_THAN, 44) | clear_under | center;
            root = dbox({root, overlay});
        } else if (mode == Mode::Edit) {
            Element overlay =
                window(text(" edit secret "),
                       vbox({
                           hbox({text("name:  "),
                                 text(keys[static_cast<std::size_t>(selected)]) | bold}),
                           hbox({text("value: "), value_input->Render()}),
                           separator(),
                           text("Enter save   Esc cancel") | dim,
                       })) |
                size(WIDTH, GREATER_THAN, 44) | clear_under | center;
            root = dbox({root, overlay});
        } else if (mode == Mode::ConfirmDelete || mode == Mode::ConfirmRotate) {
            std::string msg = mode == Mode::ConfirmDelete
                                  ? "Delete '" + keys[static_cast<std::size_t>(selected)] + "'?"
                                  : "Rotate the encryption key?";
            Element overlay =
                window(text(" confirm "), vbox({text(msg), separator(), text("y / n") | dim})) |
                clear_under | center;
            root = dbox({root, overlay});
        }
        return root;
    });

    ScreenInteractive screen = ScreenInteractive::Fullscreen();

    Component app = CatchEvent(renderer, [&](Event event) -> bool {
        if (mode == Mode::Normal) {
            if (event == Event::Character('q')) {
                screen.Exit();
                return true;
            }
            if (event == Event::Character('a')) {
                start_add();
                return true;
            }
            if (event == Event::Character('e')) {
                start_edit();
                return true;
            }
            if (event == Event::Character('r')) {
                reveal();
                return true;
            }
            if (event == Event::Character('h')) {
                remask();
                status = "hidden";
                return true;
            }
            if (event == Event::Character('R')) {
                mode = Mode::ConfirmRotate;
                return true;
            }
            if (event == Event::Character('d')) {
                if (keys.empty()) {
                    status = "no secret to delete";
                } else {
                    mode = Mode::ConfirmDelete;
                }
                return true;
            }
            return false;  // arrows / navigation fall through to the menu
        }
        if (mode == Mode::Add || mode == Mode::Edit) {
            if (event == Event::Escape) {
                cancel_form();
                return true;
            }
            if (event == Event::Return) {
                if (mode == Mode::Add) {
                    submit_add();
                } else {
                    submit_edit();
                }
                return true;
            }
            return false;  // typing falls through to the focused input
        }
        // Confirm modes: consume every key so nothing leaks to the menu.
        if (event == Event::Character('y') || event == Event::Character('Y')) {
            if (mode == Mode::ConfirmDelete) {
                do_delete();
            } else {
                do_rotate();
            }
        } else {
            mode = Mode::Normal;
            status = "cancelled";
        }
        return true;
    });

    screen.Loop(app);

    remask();
    zero(add_name);
    zero(add_value);
    return 0;
}

}  // namespace

int run_tui() {
    if (!::isatty(STDIN_FILENO) || !::isatty(STDOUT_FILENO)) {
        std::fputs("secretov tui: requires a terminal\n", stderr);
        return 1;
    }

    Paths paths = resolve_paths();
    try {
        DaemonClient daemon(paths);
        daemon.request("list");  // fail fast if unreachable/unauthorized
        return run_ui(daemon);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "secretov: %s\n", e.what());
        return 1;
    }
}

}  // namespace secretov
