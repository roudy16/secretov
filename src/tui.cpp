#include "tui.hpp"

#include <sodium.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <ftxui/component/component.hpp>
#include <ftxui/component/component_options.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/terminal.hpp>
#include <nlohmann/json.hpp>

#include "client.hpp"
#include "paths.hpp"
#include "protocol.hpp"
#include "tui_edit.hpp"

// Secret hygiene ceiling: the revealed value, the form value buffer (Edit
// prefills it with the current value) and the paste buffer are zeroed
// (sodium_memzero, whole capacity) as soon as they are re-masked, submitted,
// cancelled or the TUI exits. The detail pane wraps the revealed value as views
// into it, but FTXUI copies buffer contents and those pieces into its own render
// structures each frame, and a buffer that outgrows its reserve reallocates;
// those copies are not zeroed. Best-effort — good enough for a local TUI, not
// a hardened enclave. Upgrade path: a custom no-copy render element if it matters.

namespace secretov {

namespace {

using nlohmann::json;

// Wipes past size() too: erase/backspace leave old bytes in the capacity tail.
void zero(std::string& s) {
    s.resize(s.capacity());
    sodium_memzero(s.data(), s.size());
    s.clear();
}

// ponytail: values longer than this reallocate and leave an unzeroed copy behind.
constexpr std::size_t kSecretReserve = 4096;

// Narrower terminals stack the list above the detail pane.
constexpr int kStackedBelowColumns = 80;

// Copies a daemon reply's value into `into` and wipes the reply's own copy.
void take_value(nlohmann::json& resp, std::string& into) {
    auto found = resp.find("value");
    if (found == resp.end() || !found->is_string()) throw std::runtime_error("daemon reply has no value");
    std::string& held = found->get_ref<std::string&>();
    into.assign(held);
    zero(held);
}

bool has_control_char(const std::string& text) {
    return std::any_of(text.begin(), text.end(), [](char c) {
        auto byte = static_cast<unsigned char>(c);
        return byte < 0x20 || byte == 0x7f;
    });
}

enum class Mode { Normal, Add, Edit, ConfirmDelete, ConfirmOverwrite };

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
    std::vector<std::string> labels;  // each row's last path segment, parallel to rows
    std::set<std::string> collapsed;  // folder ids currently folded
    int selected = 0;
    std::optional<std::string> revealed;  // fetched value for the selected key
    std::string add_name;
    std::string add_value;
    int name_cursor = 0;  // byte offsets, shared with the FTXUI inputs
    int value_cursor = 0;
    bool value_masked = true;
    bool show_form_problem = false;  // set by a refused submit; then validation is live
    std::string paste_buffer;
    bool pasting = false;  // between bracketed-paste start and end markers
    std::string status = "ready";
    Mode mode = Mode::Normal;
    int active_tab = 0;  // 0 = key list, 1 = add/edit form
    int form_field = 0;  // 0 = name input, 1 = value input
    int detail_scroll = 0;     // first detail-pane line shown
    std::string detail_row_id;  // row detail_scroll belongs to; a new row starts at the top
    int list_text_width = 0;    // columns a list row may use, set each frame before the menu renders

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
                    labels.push_back(folders[d].substr(name_start));
                }
                hidden = hidden || folded;
            }
            if (!hidden) {
                std::size_t name_start = folders.empty() ? 0 : folders.back().size();
                rows.push_back({key, false, static_cast<int>(folders.size())});
                labels.push_back(key.substr(name_start));
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
            revealed.emplace();
            take_value(resp, *revealed);
            status = "revealed " + *key;
        } catch (const std::exception& e) {
            remask();
            status = e.what();
        }
    };

    auto close_form = [&] {
        zero(add_name);
        zero(add_value);
        name_cursor = 0;
        value_cursor = 0;
        value_masked = true;
        show_form_problem = false;
        mode = Mode::Normal;
        active_tab = 0;
        form_field = 0;
    };

    // The add name starts at the selected folder, so 'a' on dev/api/ or on a
    // key inside it only needs the KEY typed.
    auto start_add = [&] {
        remask();
        close_form();
        add_value.reserve(kSecretReserve);
        if (!rows.empty()) add_name = folder_prefix(row_at(selected).id);
        name_cursor = static_cast<int>(add_name.size());
        mode = Mode::Add;
        active_tab = 1;
        status = "adding secret";
    };

    // Edit prefills the current value (masked until Ctrl-R) so a small fix
    // doesn't mean retyping a token; the buffer is zeroed on every way out.
    auto start_edit = [&] {
        std::optional<std::string> key = need_key("edit");
        if (!key) return;
        remask();
        close_form();
        add_value.reserve(kSecretReserve);
        try {
            json resp = daemon.request("get", *key);
            take_value(resp, add_value);
        } catch (const std::exception& e) {
            zero(add_value);
            status = e.what();
            return;
        }
        value_cursor = static_cast<int>(add_value.size());
        mode = Mode::Edit;
        active_tab = 1;
        form_field = 1;
        status = "editing " + *key;
    };

    auto cancel_form = [&] {
        close_form();
        status = "cancelled";
    };

    // What stops the open form from saving, if anything. Add and Edit share
    // the empty-value rule.
    auto form_problem = [&]() -> std::optional<std::string> {
        if (mode == Mode::Add) {
            if (std::optional<std::string> error = key_name_error(trim_key_name(add_name))) return error;
        }
        if (add_value.empty()) return "value required";
        return std::nullopt;
    };

    auto key_exists = [&](const std::string& key) { return std::binary_search(keys.begin(), keys.end(), key); };

    // Writes the form value under `key`; the form stays open on failure.
    auto save_form = [&](const std::string& key, const std::string& verb) {
        try {
            daemon.request("set", key, add_value);
        } catch (const std::exception& e) {
            status = e.what();
            return false;
        }
        close_form();
        status = verb + " " + key;
        refresh(key);
        return true;
    };

    auto submit_add = [&] {
        if (std::optional<std::string> problem = form_problem()) {
            show_form_problem = true;
            status = *problem;
            return;
        }
        std::string name = trim_key_name(add_name);
        std::string selected_id = rows.empty() ? "" : row_at(selected).id;
        refresh(selected_id);  // the CLI may have added or removed this key meanwhile
        if (key_exists(name)) {
            mode = Mode::ConfirmOverwrite;
            status = "'" + name + "' already exists";
            return;
        }
        save_form(name, "added");
    };

    auto submit_edit = [&] {
        if (std::optional<std::string> problem = form_problem()) {
            show_form_problem = true;
            status = *problem;
            return;
        }
        save_form(current_key().value_or(""), "updated");
    };

    // Bracketed paste arrives whole here; it only ever lands in a form input,
    // so a pasted newline can neither submit nor run Normal-mode keys.
    auto finish_paste = [&] {
        if (mode != Mode::Add && mode != Mode::Edit) {
            status = "paste ignored: open a form with 'a' or 'e' first";
        } else if (form_field == 0) {
            if (has_control_char(paste_buffer)) {
                status = "paste refused: a name is one line";
            } else {
                name_cursor = std::clamp(name_cursor, 0, static_cast<int>(add_name.size()));
                add_name.insert(static_cast<std::size_t>(name_cursor), paste_buffer);
                name_cursor += static_cast<int>(paste_buffer.size());
            }
        } else {
            value_cursor = std::clamp(value_cursor, 0, static_cast<int>(add_value.size()));
            add_value.insert(static_cast<std::size_t>(value_cursor), paste_buffer);
            value_cursor += static_cast<int>(paste_buffer.size());
            bool ends_in_newline = !paste_buffer.empty() && paste_buffer.back() == '\n';
            auto line_count = std::count(paste_buffer.begin(), paste_buffer.end(), '\n') + (ends_in_newline ? 0 : 1);
            status = "pasted " + std::to_string(line_count) + (line_count == 1 ? " line" : " lines");
        }
        zero(paste_buffer);
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

    // Marker, indentation and fold glyph in front of a row's name. Every row
    // puts its glyph at column 2*depth, so a top-level secret never lines up
    // with a folder's children.
    auto row_prefix = [&](int i, bool is_selected) {
        const Row& row = row_at(i);
        const char* glyph = !row.dir ? "· " : collapsed.count(row.id) > 0 ? "▸ " : "▾ ";
        return std::string(is_selected ? "> " : "  ") + std::string(2 * static_cast<std::size_t>(row.depth), ' ') +
               glyph;
    };

    MenuOption menu_opt = MenuOption::Vertical();
    menu_opt.on_change = remask;
    // Names are cut to the pane instead of letting the menu scroll sideways,
    // which would hide the marker and the tree structure.
    menu_opt.entries_option.transform = [&](const EntryState& entry) {
        std::string prefix = row_prefix(entry.index, entry.active);
        Element line = text(prefix + ellipsize(entry.label, list_text_width - text_columns(prefix)));
        if (row_at(entry.index).dir) line |= bold;
        if (entry.active) line |= inverted;
        return line;
    };
    Component menu = Menu(&labels, &selected, menu_opt);

    InputOption name_opt;
    name_opt.multiline = false;
    name_opt.cursor_position = &name_cursor;
    Component name_input = Input(&add_name, "env/project/KEY", name_opt);
    InputOption value_opt;
    value_opt.password = &value_masked;
    value_opt.cursor_position = &value_cursor;
    Component value_input = Input(&add_value, "type or paste", value_opt);
    // Edit draws no name input, so it must not be focusable there either.
    Component form =
        Container::Vertical({Maybe(name_input, [&] { return mode == Mode::Add; }), value_input}, &form_field);

    Component tab = Container::Tab({menu, form}, &active_tab);

    ScreenInteractive screen = ScreenInteractive::Fullscreen();

    // A blank margin keeps a modal's border from merging with the pane borders under it.
    auto modal = [](Element dialog) {
        return hbox({text(" "), vbox({text(" "), std::move(dialog), text(" ")}), text(" ")}) | clear_under | center;
    };

    auto renderer = Renderer(tab, [&] {
        // FTXUI sizes its screen only after Render, so a resize would lag a
        // frame behind screen.dimx(); ask the terminal directly.
        Dimensions terminal = Terminal::Size();
        bool stacked = terminal.dimx < kStackedBelowColumns;
        int panes_height = std::max(terminal.dimy - 2, 6);  // minus hint line and status bar
        int list_width = terminal.dimx;
        int list_height = stacked ? panes_height / 2 : panes_height;
        if (!stacked) {
            int longest = 0;
            for (int i = 0; i < static_cast<int>(rows.size()); ++i) {
                longest = std::max(longest, text_columns(row_prefix(i, false)) +
                                                text_columns(labels[static_cast<std::size_t>(i)]));
            }
            // +3: borders and scroll indicator. At most 2/5 so the detail pane keeps room for a value.
            list_width = std::clamp(longest + 3, 24, terminal.dimx * 2 / 5);
        }
        list_text_width = list_width - 3;
        Element list_pane = window(text(" secrets "),
                                   rows.empty() ? (text("(empty)") | dim | center)
                                                : (menu->Render() | vscroll_indicator | yframe)) |
                            size(WIDTH, EQUAL, list_width) | size(HEIGHT, EQUAL, list_height);

        int detail_width = stacked ? terminal.dimx : terminal.dimx - list_width;
        int detail_height = stacked ? panes_height - list_height : panes_height;
        int detail_text_width = detail_width - 2;
        int detail_text_height = std::max(detail_height - 2, 1);
        Elements detail_lines;
        auto add_wrapped = [&](std::string_view content, Decorator style) {
            for (std::string_view piece : wrap_lines(content, detail_text_width)) {
                detail_lines.push_back(text(std::string(piece)) | style);
            }
        };
        std::string detail_id = rows.empty() ? "" : row_at(selected).id;
        if (detail_id != detail_row_id) {
            detail_row_id = detail_id;
            detail_scroll = 0;
        }
        if (rows.empty()) {
            detail_lines.push_back(text("press 'a' to add a secret") | dim);
        } else if (row_at(selected).dir) {
            const std::string& folder = row_at(selected).id;
            std::size_t count = 0;
            for (const std::string& key : keys) {
                if (key.compare(0, folder.size(), folder) == 0) ++count;
            }
            detail_lines.push_back(text("folder:") | dim);
            add_wrapped(folder, bold);
            detail_lines.push_back(separator());
            detail_lines.push_back(text(std::to_string(count) + " secret(s)"));
        } else {
            detail_lines.push_back(text("name:") | dim);
            add_wrapped(row_at(selected).id, bold);
            detail_lines.push_back(separator());
            detail_lines.push_back(text("value:") | dim);
            if (revealed) {
                add_wrapped(*revealed, nothing);
            } else {
                detail_lines.push_back(text("••••••••"));
                detail_lines.push_back(text("(press 'r' to reveal)") | dim);
            }
        }
        int detail_line_count = static_cast<int>(detail_lines.size());
        bool detail_overflows = detail_line_count > detail_text_height;
        detail_scroll = std::clamp(detail_scroll, 0, std::max(0, detail_line_count - detail_text_height));
        int detail_last = std::min(detail_line_count, detail_scroll + detail_text_height);
        std::string detail_title = " detail ";
        if (detail_overflows) {
            detail_title += std::to_string(detail_scroll + 1) + "-" + std::to_string(detail_last) + "/" +
                            std::to_string(detail_line_count) + " J/K scroll ";
        }
        Elements shown_lines(std::make_move_iterator(detail_lines.begin() + detail_scroll),
                             std::make_move_iterator(detail_lines.begin() + detail_last));
        Element detail_pane = window(text(detail_title), vbox(std::move(shown_lines))) |
                              size(WIDTH, EQUAL, detail_width) | size(HEIGHT, EQUAL, detail_height);

        std::vector<std::string> hint_items;
        if (mode == Mode::Normal) {
            hint_items = {"j/k move", revealed ? "r hide" : "r reveal"};
            if (detail_overflows) hint_items.push_back("J/K scroll");
            hint_items.insert(hint_items.end(), {"h/l fold", "a add", "e edit", "d delete", "q quit"});
        } else if (mode == Mode::Add || mode == Mode::Edit) {
            bool in_name = mode == Mode::Add && form_field == 0;
            hint_items = {in_name ? "Enter next field" : "Enter save"};
            if (mode == Mode::Add) hint_items.push_back("Tab switch field");
            hint_items.insert(hint_items.end(), {value_masked ? "Ctrl-R show value" : "Ctrl-R hide value",
                                                 "Ctrl-U/W erase", "Ctrl-A/E line start/end", "Esc cancel"});
        } else {
            hint_items = {"y yes", "Enter/Esc/any other key no"};
        }
        Element hints = text(" " + fit_hints(hint_items, terminal.dimx - 2) + " ") | dim | center;

        // The message comes first and shrinks last; the socket path only shows when it fits.
        std::string message = " " + status + " ";
        std::string key_count = " keys: " + std::to_string(keys.size()) + " ";
        std::string socket = " " + daemon.socket_path() + " ";
        Elements status_parts = {text(message) | flex, separator(), text(key_count)};
        if (text_columns(message) + text_columns(key_count) + text_columns(socket) + 2 <= terminal.dimx) {
            status_parts.push_back(separator());
            status_parts.push_back(text(socket) | dim);
        }
        Element status_bar = hbox(std::move(status_parts)) | inverted;

        Element panes = stacked ? vbox({list_pane, detail_pane}) : hbox({list_pane, detail_pane});
        Element root = vbox({panes | flex, hints, status_bar});

        // The overwrite confirm replaces the form rather than sitting on it: a
        // modal's blank margin would cut through the form's border.
        if (mode == Mode::Add || mode == Mode::Edit) {
            bool adding = mode == Mode::Add;
            int overlay_width = std::clamp(terminal.dimx - 4, 20, 72);
            Elements lines;
            if (adding) {
                lines.push_back(hbox({text("name:  "), name_input->Render()}));
                std::string name = trim_key_name(add_name);
                if (key_exists(name)) {
                    lines.push_back(text("       exists: saving will ask to overwrite") | color(Color::Yellow));
                }
            } else {
                lines.push_back(
                    hbox({text("name:  "), text(ellipsize(current_key().value_or(""), overlay_width - 9)) | bold}));
            }
            // ponytail: 8 visible lines; taller values scroll with the cursor.
            lines.push_back(hbox({text("value: "), value_input->Render() | size(HEIGHT, LESS_THAN, 8)}));
            std::optional<std::string> problem = show_form_problem ? form_problem() : std::nullopt;
            if (problem) lines.push_back(text("       " + *problem) | color(Color::Red));
            root = dbox({root, modal(window(text(adding ? " add secret " : " edit secret "), vbox(std::move(lines))) |
                                     size(WIDTH, EQUAL, overlay_width))});
        }
        if (mode == Mode::ConfirmDelete || mode == Mode::ConfirmOverwrite) {
            std::string question = mode == Mode::ConfirmDelete
                                       ? "Delete '" + current_key().value_or("") + "'? [y/N]"
                                       : "Overwrite '" + trim_key_name(add_name) + "'? [y/N]";
            int question_width = std::min(text_columns(question), std::max(terminal.dimx - 6, 10));
            Elements question_lines;
            for (std::string_view piece : wrap_lines(question, question_width)) {
                question_lines.push_back(text(std::string(piece)));
            }
            root = dbox({root, modal(window(text(" confirm "), vbox(std::move(question_lines))))});
        }
        return root;
    });

    const Event paste_start = Event::Special("\x1b[200~");
    const Event paste_end = Event::Special("\x1b[201~");

    Component app = CatchEvent(renderer, [&](Event event) -> bool {
        if (event == Event::CtrlC) {  // quit through Exit so the buffers below get zeroed
            screen.Exit();
            return true;
        }
        if (event == paste_start) {
            pasting = true;
            zero(paste_buffer);
            paste_buffer.reserve(kSecretReserve);
            return true;
        }
        if (pasting) {
            if (event == paste_end) {
                pasting = false;
                finish_paste();
            } else if (event == Event::Escape) {  // a lost end marker must not swallow input forever
                pasting = false;
                zero(paste_buffer);
                status = "paste aborted";
            } else if (event.is_character()) {
                paste_buffer += event.character();
            } else if (event == Event::Return) {
                paste_buffer += '\n';
            } else if (event == Event::Tab) {
                paste_buffer += '\t';
            }
            return true;
        }
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
            if (event == Event::Character('J') || event == Event::Character('K')) {
                detail_scroll += event == Event::Character('J') ? 1 : -1;  // the renderer clamps it
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
                if (mode == Mode::Add && form_field == 0) {
                    form_field = 1;
                } else if (mode == Mode::Add) {
                    submit_add();
                } else {
                    submit_edit();
                }
                return true;
            }
            if (event == Event::CtrlR) {
                value_masked = !value_masked;
                return true;
            }
            std::string& text_in_focus = form_field == 0 ? add_name : add_value;
            int& cursor_in_focus = form_field == 0 ? name_cursor : value_cursor;
            if (event == Event::CtrlU) {
                erase_to_line_start(text_in_focus, cursor_in_focus);
                return true;
            }
            if (event == Event::CtrlW) {
                erase_word_before(text_in_focus, cursor_in_focus);
                return true;
            }
            if (event == Event::CtrlA) {
                cursor_in_focus = line_start(text_in_focus, cursor_in_focus);
                return true;
            }
            if (event == Event::CtrlE) {
                cursor_in_focus = line_end(text_in_focus, cursor_in_focus);
                return true;
            }
            return false;  // typing falls through to the focused input
        }
        // Confirm modes consume every key so nothing leaks to the menu or form.
        bool confirmed = event == Event::Character('y') || event == Event::Character('Y');
        if (mode == Mode::ConfirmOverwrite) {
            if (!confirmed || !save_form(trim_key_name(add_name), "updated")) mode = Mode::Add;
            if (!confirmed) status = "not saved; edit the name or Esc";
            return true;
        }
        if (confirmed) {
            do_delete();
        } else {
            mode = Mode::Normal;
            status = "cancelled";
        }
        return true;
    });

    screen.ForceHandleCtrlC(false);
    std::cout << "\x1b[?2004h" << std::flush;  // bracketed paste; FTXUI doesn't request it
    screen.Loop(app);
    std::cout << "\x1b[?2004l" << std::flush;

    remask();
    zero(add_name);
    zero(add_value);
    zero(paste_buffer);
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
