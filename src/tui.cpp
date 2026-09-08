#include "tui.hpp"

#include <sodium.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <ftxui/component/component.hpp>
#include <ftxui/component/component_options.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/string.hpp>
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

enum class Mode { Normal, Add, Edit, ConfirmDelete };

// One visible line of the key tree: a folder ("dev/proj/") or a secret.
struct Row {
    std::string id;  // full key, or folder prefix ending in '/'
    bool dir;
    int depth;
};

int run_ui(DaemonClient& daemon) {
    using namespace ftxui;

    std::vector<std::string> keys;    // every key, sorted
    std::vector<Row> rows;            // visible tree rows
    std::vector<std::string> labels;  // what the menu draws, parallel to rows
    std::set<std::string> collapsed;  // folder ids currently folded
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

    auto row_at = [&](int i) -> const Row& { return rows[static_cast<std::size_t>(i)]; };

    // Full key of the selected row; nullopt on a folder or an empty list.
    auto current_key = [&]() -> std::optional<std::string> {
        if (rows.empty() || row_at(selected).dir) return std::nullopt;
        return row_at(selected).id;
    };

    // current_key(), with a status message naming the blocked action.
    auto need_key = [&](const char* action) -> std::optional<std::string> {
        std::optional<std::string> key = current_key();
        if (!key) status = std::string(rows.empty() ? "no secret to " : "select a secret to ") + action;
        return key;
    };

    // Rebuild the visible rows from `keys` and `collapsed`. Keys are sorted,
    // so a folder's members are contiguous and its row is emitted the first
    // time the prefix appears. `select_id` re-selects a row by id afterwards.
    auto rebuild_rows = [&](const std::string& select_id) {
        rows.clear();
        labels.clear();
        std::vector<std::string> branch;  // folder ids open along the current key
        for (const std::string& key : keys) {
            std::vector<std::string> folders;  // "a/", "a/b/", ... for this key
            for (std::size_t slash = key.find('/'); slash != std::string::npos;
                 slash = key.find('/', slash + 1)) {
                folders.push_back(key.substr(0, slash + 1));
            }
            std::size_t shared = 0;
            while (shared < folders.size() && shared < branch.size() &&
                   branch[shared] == folders[shared]) {
                ++shared;
            }
            branch.resize(shared);
            bool hidden = false;
            for (const std::string& f : branch) hidden = hidden || collapsed.count(f) > 0;
            for (std::size_t d = shared; d < folders.size(); ++d) {
                branch.push_back(folders[d]);
                bool folded = collapsed.count(folders[d]) > 0;
                if (!hidden) {
                    std::size_t name_start = d == 0 ? 0 : folders[d - 1].size();
                    rows.push_back({folders[d], true, static_cast<int>(d)});
                    labels.push_back(std::string(2 * d, ' ') + (folded ? "▸ " : "▾ ") +
                                     folders[d].substr(name_start));
                }
                hidden = hidden || folded;
            }
            if (!hidden) {
                std::size_t name_start = folders.empty() ? 0 : folders.back().size();
                rows.push_back({key, false, static_cast<int>(folders.size())});
                labels.push_back(std::string(2 * folders.size() + 2, ' ') + key.substr(name_start));
            }
        }
        if (!select_id.empty()) {
            for (std::size_t i = 0; i < rows.size(); ++i) {
                if (rows[i].id == select_id) selected = static_cast<int>(i);
            }
        }
        if (selected >= static_cast<int>(rows.size())) selected = static_cast<int>(rows.size()) - 1;
        if (selected < 0) selected = 0;
    };

    auto refresh = [&](const std::string& select_id) {
        remask();
        try {
            json resp = daemon.request("list");
            keys = resp.value("keys", std::vector<std::string>{});
        } catch (const std::exception& e) {
            status = e.what();
            return;
        }
        std::sort(keys.begin(), keys.end());
        rebuild_rows(select_id);
    };

    // Fold state of the selected folder: nullopt toggles, true unfolds, false folds.
    auto fold = [&](std::optional<bool> open) {
        if (rows.empty() || !row_at(selected).dir) return;
        std::string id = row_at(selected).id;  // copy: rebuild_rows invalidates rows
        bool folded = collapsed.count(id) > 0;
        bool want_folded = open ? !*open : !folded;
        if (want_folded == folded) return;
        if (want_folded) {
            collapsed.insert(id);
        } else {
            collapsed.erase(id);
        }
        rebuild_rows(id);
    };

    // Move the selection to the enclosing folder row, if any.
    auto go_parent = [&] {
        if (rows.empty()) return;
        int depth = row_at(selected).depth;
        for (int i = selected - 1; i >= 0; --i) {
            if (row_at(i).dir && row_at(i).depth < depth) {
                selected = i;
                remask();
                return;
            }
        }
    };

    auto reveal = [&] {
        std::optional<std::string> key = need_key("reveal");
        if (!key) return;
        try {
            json resp = daemon.request("get", *key);
            remask();
            revealed = resp.value("value", std::string{});
            status = "revealed " + *key;
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
        std::optional<std::string> key = need_key("edit");
        if (!key) return;
        remask();
        zero(add_value);
        mode = Mode::Edit;
        active_tab = 1;
        form_field = 1;
        status = "editing " + *key;
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
        std::string key = current_key().value_or("");
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
        std::string key = current_key().value_or("");
        try {
            daemon.request("delete", key, std::nullopt);
            status = "deleted " + key;
            refresh("");
        } catch (const std::exception& e) {
            status = e.what();
        }
        mode = Mode::Normal;
    };

    refresh("");

    MenuOption menu_opt = MenuOption::Vertical();
    menu_opt.on_change = remask;
    Component menu = Menu(&labels, &selected, menu_opt);

    Component name_input = Input(&add_name, "name");
    InputOption value_opt;
    value_opt.password = true;
    Component value_input = Input(&add_value, "value", value_opt);
    Component form = Container::Vertical({name_input, value_input}, &form_field);

    Component tab = Container::Tab({menu, form}, &active_tab);

    ScreenInteractive screen = ScreenInteractive::Fullscreen();

    auto renderer = Renderer(tab, [&] {
        // Wide enough for the longest visible label, capped so the detail
        // pane keeps room for a value.
        int list_width = 30;
        for (const std::string& label : labels) {
            list_width = std::max(list_width, string_width(label) + 6);
        }
        list_width = std::min(list_width, std::max(30, screen.dimx() * 3 / 5));
        Element list_pane = window(text(" secrets "),
                                   rows.empty()
                                       ? (text("(empty)") | dim | center)
                                       : (menu->Render() | vscroll_indicator | frame)) |
                            size(WIDTH, EQUAL, list_width);

        Element detail_body;
        if (rows.empty()) {
            detail_body = text("press 'a' to add a secret") | dim | center;
        } else if (row_at(selected).dir) {
            const std::string& folder = row_at(selected).id;
            std::size_t count = 0;
            for (const std::string& key : keys) {
                if (key.compare(0, folder.size(), folder) == 0) ++count;
            }
            detail_body = vbox({
                hbox({text("folder: "), text(folder) | bold}),
                separator(),
                text(std::to_string(count) + " secret(s)   h/l to fold/unfold") | dim,
            });
        } else {
            Element value_line = revealed ? text(*revealed) : text("••••••••");
            detail_body = vbox({
                hbox({text("name:  "), text(row_at(selected).id) | bold}),
                separator(),
                hbox({text("value: "), value_line}),
                text(revealed ? "" : "(press 'r' to reveal)") | dim,
            });
        }
        Element detail_pane = window(text(" detail "), detail_body) | flex;

        Element hints = text(" a add   e edit   d delete   r reveal/hide   j/k move   h/l fold   q quit ") |
                        dim | center;
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
                           hbox({text("name:  "), text(current_key().value_or("")) | bold}),
                           hbox({text("value: "), value_input->Render()}),
                           separator(),
                           text("Enter save   Esc cancel") | dim,
                       })) |
                size(WIDTH, GREATER_THAN, 44) | clear_under | center;
            root = dbox({root, overlay});
        } else if (mode == Mode::ConfirmDelete) {
            std::string msg = "Delete '" + current_key().value_or("") + "'?";
            Element overlay =
                window(text(" confirm "), vbox({text(msg), separator(), text("y / n") | dim})) |
                clear_under | center;
            root = dbox({root, overlay});
        }
        return root;
    });

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
                if (revealed) {
                    remask();
                    status = "hidden";
                } else {
                    reveal();
                }
                return true;
            }
            if (event == Event::Character('d')) {
                if (need_key("delete")) mode = Mode::ConfirmDelete;
                return true;
            }
            if (event == Event::Return || event == Event::Character(' ')) {
                if (current_key()) {
                    reveal();
                } else {
                    fold(std::nullopt);
                }
                return true;
            }
            if (event == Event::ArrowLeft || event == Event::Character('h')) {
                bool open_folder = !rows.empty() && row_at(selected).dir &&
                                   collapsed.count(row_at(selected).id) == 0;
                if (open_folder) {
                    fold(false);
                } else {
                    go_parent();
                }
                return true;
            }
            if (event == Event::ArrowRight || event == Event::Character('l')) {
                fold(true);
                return true;
            }
            return false;  // up/down and j/k fall through to the menu
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
        // Confirm-delete mode: consume every key so nothing leaks to the menu.
        if (event == Event::Character('y') || event == Event::Character('Y')) {
            do_delete();
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
