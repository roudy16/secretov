#include "tui.hpp"

#include <fcntl.h>
#include <sodium.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <ftxui/component/component.hpp>
#include <ftxui/component/component_options.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/terminal.hpp>
#include <nlohmann/json.hpp>

#include "client.hpp"
#include "manifest.hpp"
#include "paths.hpp"
#include "protocol.hpp"
#include "tui_edit.hpp"

// Secret hygiene ceiling: the revealed value, the form value buffer (Edit
// prefills it with the current value), the paste buffer and the copy buffers
// are zeroed (sodium_memzero, whole capacity) as soon as they are re-masked (by
// hand, on selection change or after kRevealFor), submitted, cancelled, written
// to the terminal, or the TUI exits. DaemonClient zeroes its request json, the
// request line, the socket write copy and the raw reply line. Not zeroed: the
// FTXUI render structures that copy buffer contents (and the detail pane's
// wrapped pieces) each frame, FTXUI's input parser and the Event objects that
// carry each typed or pasted character, a buffer that outgrows its reserve and
// reallocates, nlohmann's serializer growth copies while it writes the request
// line, and its parser scratch while it reads a reply — DESIGN.md's
// client-process copies ceiling. Best-effort — good enough for a local TUI, not
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

using Clock = std::chrono::steady_clock;
constexpr auto kRevealFor = std::chrono::seconds(60);  // a revealed value re-masks after this
constexpr auto kInfoFor = std::chrono::seconds(4);     // an info message clears after this; errors stay
// A paste without bracketed-paste markers arrives as a burst of keys, which
// FTXUI reads 128 bytes a frame (~17 ms apart): an Enter or Tab followed this
// soon by more input is a pasted newline or tab, and keys this soon after a
// save are dropped.
constexpr auto kPasteBurst = std::chrono::milliseconds(50);
constexpr auto kAfterSubmitQuiet = std::chrono::milliseconds(100);

const char* const kStartDaemonHint = "start it with 'scripts/service start' (systemd user unit) or 'secretov daemon'";
const char* const kBusyDaemonHint =
    "another client holds its socket: 'ss -xp | grep secretov.sock' shows the peer inode last; "
    "'ss -xp | grep <that inode>' names the holder; stop it";

// Copies a daemon reply's value into `into` and wipes the reply's own copy.
void take_value(nlohmann::json& resp, std::string& into) {
    auto found = resp.find("value");
    if (found == resp.end() || !found->is_string()) throw std::runtime_error("daemon reply has no value");
    std::string& held = found->get_ref<std::string&>();
    into.assign(held);
    zero(held);
}

bool is_busy(const DaemonUnreachable& e) { return std::string_view(e.what()).starts_with("daemon busy"); }

// Why a sent request got no reply, short enough for the status bar.
std::string no_reply_reason(const DaemonUnreachable& e) {
    return is_busy(e) ? "no reply in 5 s" : "daemon hung up";
}

bool has_control_char(const std::string& text) {
    return std::any_of(text.begin(), text.end(), [](char c) {
        auto byte = static_cast<unsigned char>(c);
        return byte < 0x20 || byte == 0x7f;
    });
}

// Puts the escape on the controlling terminal itself, past FTXUI's frame output.
void write_to_terminal(const std::string& bytes) {
    int fd = ::open("/dev/tty", O_WRONLY | O_NOCTTY | O_CLOEXEC);
    if (fd < 0) throw std::runtime_error(std::string("open /dev/tty: ") + std::strerror(errno));
    std::size_t written = 0;
    while (written < bytes.size()) {
        ssize_t n = ::write(fd, bytes.data() + written, bytes.size() - written);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            int write_errno = errno;
            ::close(fd);
            throw std::runtime_error(std::string("write to terminal: ") + std::strerror(write_errno));
        }
        written += static_cast<std::size_t>(n);
    }
    ::close(fd);
}

// Store keys the cwd's .secretov.yaml references, found and vetted exactly as
// the CLI does (find_manifest_upward + load_manifest).
struct ProjectMarks {
    std::string project;  // empty: nothing to mark
    std::map<std::string, std::vector<std::string>> env_vars_by_key;  // "STRIPE_KEY (dev)"
    std::string problem;  // why a manifest that was found marks nothing
};

ProjectMarks load_project_marks() {
    ProjectMarks marks;
    std::optional<std::string> manifest_path;
    try {
        manifest_path = find_manifest_upward(std::filesystem::current_path().string());
        if (!manifest_path) return marks;
        Manifest manifest = load_manifest(*manifest_path);
        for (const auto& [env, entries] : manifest.envs) {
            for (const SecretEntry& entry : entries) {
                marks.env_vars_by_key[entry.key].push_back(printable(entry.env_var + " (" + env + ")"));
            }
        }
        marks.project = printable(manifest.project);
    } catch (const std::exception& e) {
        marks.env_vars_by_key.clear();
        // The status bar is one line: name the manifest relative to the cwd so the reason fits.
        std::string reason = e.what();
        std::error_code relative_error;
        std::string short_path =
            manifest_path ? std::filesystem::relative(*manifest_path, relative_error).string() : "";
        if (manifest_path && !relative_error) {
            for (std::size_t at = reason.find(*manifest_path); at != std::string::npos;
                 at = reason.find(*manifest_path, at + short_path.size())) {
                reason.replace(at, manifest_path->size(), short_path);
            }
        }
        marks.problem = "nothing marked: " + reason;
    }
    return marks;
}

enum class Mode { Normal, Filter, Help, Add, Edit, ConfirmDelete, ConfirmOverwrite };

struct HelpLine {
    const char* keys;  // nullptr: `text` is a section heading
    const char* text;
};

const HelpLine kHelp[] = {
    {nullptr, "tree"},
    {"j/k ↑/↓ PgUp/PgDn", "move"},
    {"g/G Home/End", "top / bottom"},
    {"h/l ←/→", "fold or go to parent / unfold or go to first child"},
    {"Enter Space r", "reveal or hide (folder: fold); re-masks after 60 s"},
    {"c", "copy the value to the clipboard (OSC 52), unrevealed"},
    {"J/K", "scroll the detail pane"},
    {"/  Esc", "filter keys / clear the filter and the message"},
    {"a  e  d", "add, edit, delete"},
    {"R", "reload the list from the daemon"},
    {"?  F1", "this help (j/k scroll it, any other key closes it)"},
    {"q  Ctrl-C", "quit (Ctrl-Z suspend is off: it would turn off safe paste)"},
    {"mouse", "click selects (a folder also folds), wheel moves"},
    {"◆", "key used by this directory's .secretov.yaml"},
    {nullptr, "filter (/)"},
    {"type  Backspace", "narrow to keys containing it (any case) / erase"},
    {"Ctrl-U", "erase the whole filter"},
    {"↑/↓  Enter  Esc", "move / keep the filter / clear it"},
    {nullptr, "add / edit form"},
    {"Enter", "next field (add name) or save"},
    {"Tab  Shift-Tab", "switch field (add only)"},
    {"Ctrl-R", "show or hide the value"},
    {"Ctrl-U  Ctrl-W", "erase to line start / previous word or path segment"},
    {"Ctrl-A  Ctrl-E", "line start / end"},
    {"Esc", "cancel"},
    {nullptr, "confirm [y/N]"},
    {"y", "yes; Enter, Esc or any other key: no"},
};

// One visible line of the key tree: a folder ("dev/proj/") or a secret.
struct Row {
    std::string id;  // full key, or folder prefix ending in '/'
    bool dir;
    int depth;
};

int run_ui(DaemonClient& daemon, const ProjectMarks& marks) {
    using namespace ftxui;

    std::vector<std::string> keys;    // every key, sorted
    std::vector<Row> rows;            // visible tree rows
    std::vector<std::string> labels;  // each row's last path segment, parallel to rows
    std::set<std::string> collapsed;  // folder ids currently folded; never written to disk
    int selected = 0;
    std::string selection_id;             // row the reveal and the detail scroll belong to
    std::optional<std::string> revealed;  // fetched value for the selected key
    Clock::time_point revealed_at;
    std::string filter;  // keys shown must contain this; folders stay open while it is set
    std::string add_name;
    std::string add_value;
    int name_cursor = 0;  // byte offsets, shared with the FTXUI inputs
    int value_cursor = 0;
    bool value_masked = true;
    bool show_form_problem = false;  // set by a refused submit; then validation is live
    std::string paste_buffer;
    bool pasting = false;  // between bracketed-paste start and end markers
    std::optional<Clock::time_point> held_key_since;  // a form Enter, or a Tab in the value, held for kPasteBurst
    bool held_key_is_tab = false;
    Clock::time_point ignore_keys_until;  // kAfterSubmitQuiet after a submit
    int help_scroll = 0;
    std::string status;
    bool status_is_error = false;  // errors stay until the next key; info expires after kInfoFor
    Clock::time_point status_at;
    // Of the last call: Unreachable (not running, hung up) leaves the tree stale;
    // Busy means another client held the daemon past the reply timeout.
    enum class DaemonState { Ok, Busy, Unreachable };
    DaemonState daemon_state = DaemonState::Ok;
    Mode mode = Mode::Normal;
    int active_tab = 0;  // 0 = key list, 1 = add/edit form
    int form_field = 0;  // 0 = name input, 1 = value input
    int detail_scroll = 0;     // first detail-pane line shown
    bool keep_value_in_view = false;  // set by a reveal, cleared by J/K: the detail pane follows the value
    int list_text_width = 0;   // columns a list row may use, set each frame before the menu renders

    auto say = [&](std::string message) {
        status = std::move(message);
        status_is_error = false;
        status_at = Clock::now();
    };
    auto complain = [&](std::string message) {
        status = std::move(message);
        status_is_error = true;
    };

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
        if (!key) say(std::string(rows.empty() ? "no secret to " : "select a secret to ") + action);
        return key;
    };

    // Runs before every event and every frame, so leaving a row re-masks its
    // value before the next key acts: a quick 'j r' reveals the new row.
    auto sync_selection = [&] {
        std::string id = rows.empty() ? "" : row_at(selected).id;
        if (id == selection_id) return;
        selection_id = id;
        remask();
        detail_scroll = 0;
    };

    auto select_row = [&](const std::string& id) {
        for (std::size_t i = 0; i < rows.size(); ++i) {
            if (rows[i].id == id) {
                selected = static_cast<int>(i);
                return true;
            }
        }
        return false;
    };

    auto is_folded = [&](const std::string& folder_id) { return filter.empty() && collapsed.count(folder_id) > 0; };

    // Unfolds every folder above `id` so its row is visible.
    auto expand_to = [&](const std::string& id) {
        for (std::size_t slash = id.find('/'); slash != std::string::npos && slash + 1 < id.size();
             slash = id.find('/', slash + 1)) {
            collapsed.erase(id.substr(0, slash + 1));
        }
    };

    // Rebuild the visible rows from `keys`, `filter` and `collapsed`. Keys are
    // sorted, so a folder's members are contiguous and its row is emitted the
    // first time the prefix appears. Returns whether `select_id` was found and
    // selected; otherwise the selection keeps its index.
    auto rebuild_rows = [&](const std::string& select_id) {
        rows.clear();
        labels.clear();
        std::vector<std::string> branch;  // folder ids open along the current key
        for (const std::string& key : keys) {
            if (!contains_ignore_case(key, filter)) continue;
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
            for (const std::string& f : branch) hidden = hidden || is_folded(f);
            for (std::size_t d = shared; d < folders.size(); ++d) {
                branch.push_back(folders[d]);
                if (!hidden) {
                    std::size_t name_start = d == 0 ? 0 : folders[d - 1].size();
                    rows.push_back({folders[d], true, static_cast<int>(d)});
                    labels.push_back(printable(std::string_view(folders[d]).substr(name_start)));
                }
                hidden = hidden || is_folded(folders[d]);
            }
            if (!hidden) {
                std::size_t name_start = folders.empty() ? 0 : folders.back().size();
                rows.push_back({key, false, static_cast<int>(folders.size())});
                labels.push_back(printable(std::string_view(key).substr(name_start)));
            }
        }
        bool found = !select_id.empty() && select_row(select_id);
        if (selected >= static_cast<int>(rows.size())) selected = static_cast<int>(rows.size()) - 1;
        if (selected < 0) selected = 0;
        return found;
    };

    // Every daemon call goes through here so the unreachable indicator tracks
    // the latest attempt.
    // ponytail: calls block the UI thread, bounded by DaemonClient's 5 s reply
    // timeout; move them to a worker thread if a busy daemon makes that bite.
    auto call = [&](const std::string& op, const std::string& key, std::optional<std::string_view> value) -> json {
        try {
            json resp = daemon.request(op, key, value);
            daemon_state = DaemonState::Ok;
            return resp;
        } catch (const DaemonUnreachable& e) {
            daemon_state = is_busy(e) ? DaemonState::Busy : DaemonState::Unreachable;
            // The socket path would push the fix off the status bar; ? shows it.
            if (e.stage == DaemonUnreachable::Stage::NotRunning) {
                throw DaemonUnreachable("daemon not running: start it (scripts/service start), then R", e.stage);
            }
            throw;
        } catch (...) {
            daemon_state = DaemonState::Ok;  // it answered, with an error
            throw;
        }
    };

    // On failure the last-known tree stays, marked stale when the daemon was unreachable.
    auto refresh = [&](const std::string& select_id) {
        remask();
        try {
            json resp = call("list", "", std::nullopt);
            keys = resp.value("keys", std::vector<std::string>{});
        } catch (const std::exception& e) {
            complain(e.what());
            return false;
        }
        std::sort(keys.begin(), keys.end());
        rebuild_rows(select_id);
        return true;
    };

    // Reports a failed call on `key`; a key deleted elsewhere also reloads the list.
    auto fail = [&](const std::exception& e, const std::string& key) {
        if (std::string_view(e.what()) == "not found" && !key.empty()) {
            refresh(key);
            complain("'" + key + "' was removed elsewhere; list reloaded");
            return;
        }
        complain(e.what());
    };

    auto reload = [&] {
        if (refresh(rows.empty() ? "" : row_at(selected).id)) {
            say("reloaded: " + std::to_string(keys.size()) + " key(s)");
        }
    };

    // Fold state of the selected folder: nullopt toggles, true unfolds, false folds.
    auto fold = [&](std::optional<bool> open) {
        if (rows.empty() || !row_at(selected).dir) return;
        if (!filter.empty()) {
            say("folders stay open while filtering; Esc clears the filter");
            return;
        }
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
                return;
            }
        }
    };

    // Re-filters, keeping the selected row if it still matches, else the first match.
    auto apply_filter = [&] {
        if (rebuild_rows(rows.empty() ? "" : row_at(selected).id)) return;
        auto first_secret = std::find_if(rows.begin(), rows.end(), [](const Row& row) { return !row.dir; });
        if (first_secret != rows.end()) selected = static_cast<int>(first_secret - rows.begin());
    };

    auto clear_filter = [&] {
        bool was_set = !filter.empty();
        zero(filter);  // a secret pasted here by mistake must not linger, even backspaced away
        if (!was_set) return;
        std::string id = rows.empty() ? "" : row_at(selected).id;
        expand_to(id);
        rebuild_rows(id);
    };

    auto reveal = [&] {
        std::optional<std::string> key = need_key("reveal");
        if (!key) return;
        remask();
        try {
            json resp = call("get", *key, std::nullopt);
            revealed.emplace();
            take_value(resp, *revealed);
            revealed_at = Clock::now();
            keep_value_in_view = true;
        } catch (const std::exception& e) {
            remask();
            fail(e, *key);
        }
    };

    auto toggle_reveal = [&] {
        if (revealed) {
            remask();
        } else {
            reveal();
        }
    };

    // Copies without revealing: the value goes straight from the reply into an
    // OSC 52 escape on the terminal, and both buffers are zeroed after.
    auto copy_value = [&] {
        std::optional<std::string> key = need_key("copy");
        if (!key) return;
        std::string value;
        std::string sequence;
        try {
            json resp = call("get", *key, std::nullopt);
            take_value(resp, value);
            sequence = osc52_copy_sequence(value);
            write_to_terminal(sequence);
            say("copied (clipboard managers may keep it): " + *key);
        } catch (const std::exception& e) {
            fail(e, *key);
        }
        zero(value);
        zero(sequence);
    };

    // Expires the reveal and info messages; driven by a once-a-second tick.
    auto expire = [&] {
        Clock::time_point now = Clock::now();
        if (revealed && now - revealed_at >= kRevealFor) {
            remask();
            say("value re-masked after 60 s");
        }
        if (!status_is_error && !status.empty() && now - status_at >= kInfoFor) status.clear();
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
        say("adding secret");
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
            json resp = call("get", *key, std::nullopt);
            take_value(resp, add_value);
        } catch (const std::exception& e) {
            zero(add_value);
            fail(e, *key);
            return;
        }
        // A multi-line value opens at its top: FTXUI's input centres the cursor,
        // so a cursor on the last line would shift every line sideways once
        // any line is wider than the input. A one-line value opens at its end.
        bool multi_line = add_value.find('\n') != std::string::npos;
        value_cursor = multi_line ? 0 : static_cast<int>(add_value.size());
        mode = Mode::Edit;
        active_tab = 1;
        form_field = 1;
        say("editing");  // the form shows the name
    };

    auto cancel_form = [&] {
        close_form();
        say("cancelled");
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

    // Writes the form value under `key` and selects it, unfolding its folders
    // (and dropping a filter it doesn't match); the form stays open on failure.
    auto save_form = [&](const std::string& key, const std::string& verb) {
        try {
            call("set", key, add_value);
        } catch (const DaemonUnreachable& e) {
            // A set is idempotent, so the form stays open for a retry either way.
            complain(e.stage == DaemonUnreachable::Stage::Sent
                         ? no_reply_reason(e) + ": '" + key + "' may still be saved; Enter retries, Esc cancels"
                         : e.what());
            return false;
        } catch (const std::exception& e) {
            complain(e.what());
            return false;
        }
        close_form();
        say(verb + " " + key);
        expand_to(key);
        if (!contains_ignore_case(key, filter)) zero(filter);
        refresh(key);
        return true;
    };

    auto submit_add = [&] {
        if (std::optional<std::string> problem = form_problem()) {
            show_form_problem = true;
            complain(*problem);
            return;
        }
        std::string name = trim_key_name(add_name);
        // The CLI may have added or removed this key meanwhile.
        if (!refresh(rows.empty() ? "" : row_at(selected).id)) return;
        if (key_exists(name)) {
            mode = Mode::ConfirmOverwrite;
            say("'" + name + "' already exists");
            return;
        }
        save_form(name, "added");
    };

    auto submit_edit = [&] {
        if (std::optional<std::string> problem = form_problem()) {
            show_form_problem = true;
            complain(*problem);
            return;
        }
        save_form(current_key().value_or(""), "updated");
    };

    auto insert_into_value = [&](std::string_view text) {
        value_cursor = std::clamp(value_cursor, 0, static_cast<int>(add_value.size()));
        add_value.insert(static_cast<std::size_t>(value_cursor), text);
        value_cursor += static_cast<int>(text.size());
    };

    // Bracketed paste arrives whole here; it only ever lands in a form input
    // or the filter, so a pasted newline can neither submit nor run Normal-mode keys.
    auto finish_paste = [&] {
        if (mode == Mode::Filter) {
            if (has_control_char(paste_buffer)) {
                complain("paste refused: the filter is one line");
            } else {
                filter += paste_buffer;
                apply_filter();
            }
        } else if (mode != Mode::Add && mode != Mode::Edit) {
            say("paste ignored: open a form with 'a' or 'e' first");
        } else if (form_field == 0) {
            if (has_control_char(paste_buffer)) {
                complain("paste refused: a name is one line");
            } else {
                name_cursor = std::clamp(name_cursor, 0, static_cast<int>(add_name.size()));
                add_name.insert(static_cast<std::size_t>(name_cursor), paste_buffer);
                name_cursor += static_cast<int>(paste_buffer.size());
            }
        } else {
            // Like `set`: a token copied with its line ending must not store it.
            if (!paste_buffer.empty() && paste_buffer.back() == '\n') paste_buffer.pop_back();
            insert_into_value(paste_buffer);
            auto line_count = std::count(paste_buffer.begin(), paste_buffer.end(), '\n') + 1;
            say("pasted " + std::to_string(line_count) + (line_count == 1 ? " line" : " lines"));
        }
        zero(paste_buffer);
    };

    // Where the selection lands after deleting the selected row: the next
    // sibling, else the previous one, else the nearest enclosing folder left,
    // else the row above the emptied folders.
    auto delete_landing = [&] {
        std::vector<std::string> candidates;
        int depth = row_at(selected).depth;
        int row_count = static_cast<int>(rows.size());
        for (int i = selected + 1; i < row_count && row_at(i).depth >= depth; ++i) {
            if (row_at(i).depth == depth) {
                candidates.push_back(row_at(i).id);
                break;
            }
        }
        for (int i = selected - 1; i >= 0 && row_at(i).depth >= depth; --i) {
            if (row_at(i).depth == depth) {
                candidates.push_back(row_at(i).id);
                break;
            }
        }
        const std::string& deleted = row_at(selected).id;
        for (std::string folder = folder_prefix(deleted); !folder.empty();
             folder = folder_prefix(std::string_view(folder).substr(0, folder.size() - 1))) {
            candidates.push_back(folder);
        }
        // Every enclosing folder emptied: the row above them.
        for (int i = selected - 1; i >= 0; --i) {
            if (deleted.compare(0, row_at(i).id.size(), row_at(i).id) != 0) {
                candidates.push_back(row_at(i).id);
                break;
            }
        }
        return candidates;
    };

    auto do_delete = [&] {
        mode = Mode::Normal;
        std::string key = current_key().value_or("");
        std::vector<std::string> landing = delete_landing();
        try {
            call("delete", key, std::nullopt);
        } catch (const DaemonUnreachable& e) {
            complain(e.stage == DaemonUnreachable::Stage::Sent
                         ? no_reply_reason(e) + ": '" + key + "' may still be deleted; R reloads to check"
                         : e.what());
            return;
        } catch (const std::exception& e) {
            fail(e, key);
            return;
        }
        say("deleted " + key);
        if (!refresh("")) return;
        for (const std::string& id : landing) {
            if (select_row(id)) break;
        }
    };

    refresh("");
    if (!marks.problem.empty()) {
        complain(marks.problem);
    } else if (!marks.project.empty()) {
        say("◆ marks keys used by project '" + marks.project + "'");
    }

    auto is_marked = [&](const Row& row) { return !row.dir && marks.env_vars_by_key.count(row.id) > 0; };

    // Marker, indentation and glyph in front of a row's name. Every row puts
    // its glyph at column 2*depth, so a top-level secret never lines up with
    // a folder's children.
    // ponytail: the indent stops where the marker, glyph and kMinLabelColumns
    // of name still fit, so deeper levels share one column; the detail pane
    // shows the full path.
    constexpr int kMinLabelColumns = 6;
    auto row_prefix = [&](int i, bool is_selected) {
        const Row& row = row_at(i);
        const char* glyph = !row.dir ? (is_marked(row) ? "◆ " : "· ") : is_folded(row.id) ? "▸ " : "▾ ";
        int indent = std::clamp(list_text_width - 4 - kMinLabelColumns, 0, 2 * row.depth);
        return std::string(is_selected ? "> " : "  ") + std::string(static_cast<std::size_t>(indent), ' ') + glyph;
    };

    MenuOption menu_opt = MenuOption::Vertical();
    // Names are cut to the pane instead of letting the menu scroll sideways,
    // which would hide the marker and the tree structure.
    menu_opt.entries_option.transform = [&](const EntryState& entry) {
        std::string prefix = row_prefix(entry.index, entry.active);
        Element line = text(prefix + ellipsize(entry.label, list_text_width - text_columns(prefix)));
        if (row_at(entry.index).dir) line |= bold;
        if (is_marked(row_at(entry.index))) line |= color(Color::Cyan);
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
        sync_selection();
        // FTXUI sizes its screen only after Render, so a resize would lag a
        // frame behind screen.dimx(); ask the terminal directly.
        Dimensions terminal = Terminal::Size();
        bool stacked = terminal.dimx < kStackedBelowColumns;

        // The message comes first and is never cut: the other parts shorten or
        // drop (from the last) until it fits, and a message too long for the
        // row gets rows of its own above them.
        struct StatusPart {
            std::string full;
            std::string compact;  // empty: dropped when short of room
            Decorator style;
            bool compacted = false;
        };
        std::vector<StatusPart> parts;
        if (daemon_state == DaemonState::Unreachable) {
            parts.push_back({" daemon unreachable: list stale ", " stale ", bold | color(Color::Red)});
        } else if (daemon_state == DaemonState::Busy) {
            parts.push_back({" daemon busy ", " busy ", bold | color(Color::Yellow)});
        }
        if (mode == Mode::Filter || !filter.empty()) {
            std::string shown = printable(filter) + (mode == Mode::Filter ? "▏" : "");
            parts.push_back({" filter: " + shown + " ", " /" + ellipsize(shown, 12) + " ", bold});
        }
        if (revealed) {
            auto left = std::chrono::ceil<std::chrono::seconds>(kRevealFor - (Clock::now() - revealed_at));
            std::string seconds = std::to_string(std::max<long long>(left.count(), 0)) + "s ";
            parts.push_back({" shown, hides in " + seconds, " " + seconds, bold});
        }
        parts.push_back({" keys: " + std::to_string(keys.size()) + " ", "", nothing});
        parts.push_back({" " + daemon.socket_path() + " ", "", dim});
        auto parts_columns = [&] {
            int columns = 0;
            for (const StatusPart& part : parts) {
                const std::string& shown = part.compacted ? part.compact : part.full;
                if (!shown.empty()) columns += text_columns(shown) + 1;  // + separator
            }
            return columns;
        };
        auto fit_parts = [&](int budget) {
            for (auto part = parts.rbegin(); part != parts.rend() && parts_columns() > budget; ++part) {
                part->compacted = true;
            }
        };
        std::string message = printable(status);
        int message_columns = text_columns(message) + 2;
        fit_parts(terminal.dimx - message_columns);
        bool message_on_own_rows = message_columns + parts_columns() > terminal.dimx;
        Decorator message_style = status_is_error ? bold | color(Color::Red) : nothing;
        Elements status_rows;
        Elements parts_row;
        if (message_on_own_rows) {
            for (StatusPart& part : parts) part.compacted = false;
            fit_parts(terminal.dimx);
            // ponytail: three rows at most; longer messages end in "…".
            std::vector<std::string> lines = word_wrap(message, terminal.dimx - 2);
            if (lines.size() > 3) {
                lines.resize(3);
                lines.back() = ellipsize(lines.back(), terminal.dimx - 3) + "…";
            }
            for (const std::string& line : lines) {
                status_rows.push_back(hbox({text(" " + line) | message_style, filler()}) | inverted);
            }
            parts_row.push_back(filler());
        } else {
            parts_row.push_back(text(" " + message + " ") | message_style | flex);
        }
        for (const StatusPart& part : parts) {
            const std::string& shown = part.compacted ? part.compact : part.full;
            if (shown.empty()) continue;
            parts_row.push_back(separator());
            parts_row.push_back(text(shown) | part.style);
        }
        status_rows.push_back(hbox(std::move(parts_row)) | inverted);
        int status_height = static_cast<int>(status_rows.size());
        Element status_bar = vbox(std::move(status_rows));

        int panes_height = std::max(terminal.dimy - 1 - status_height, 6);  // minus the hint line
        std::string list_title = " secrets ";
        if (!marks.project.empty()) list_title += "◆ " + marks.project + " ";
        if (!marks.problem.empty()) list_title += "◆ refused, see ? ";
        if (daemon_state == DaemonState::Unreachable) list_title += "(stale) ";
        int list_width = terminal.dimx;
        int list_height = stacked ? panes_height / 2 : panes_height;
        if (!stacked) {
            int longest = 0;
            for (int i = 0; i < static_cast<int>(rows.size()); ++i) {
                // Marker, uncapped indent, glyph, name.
                longest = std::max(longest, 4 + 2 * row_at(i).depth + text_columns(labels[static_cast<std::size_t>(i)]));
            }
            // +3: borders and scroll indicator. At most 2/5 so the detail pane keeps room for a value.
            int widest = terminal.dimx * 2 / 5;
            int narrowest = std::max(24, std::min(text_columns(list_title) + 2, widest));  // the title stays whole
            list_width = std::clamp(longest + 3, narrowest, widest);
        }
        list_text_width = list_width - 3;
        Element list_body = !rows.empty()       ? (menu->Render() | vscroll_indicator | yframe)
                            : !filter.empty()   ? (text("(no match)") | dim | center)
                                                : (text("(empty)") | dim | center);
        Element list_pane =
            window(text(list_title), list_body) | size(WIDTH, EQUAL, list_width) | size(HEIGHT, EQUAL, list_height);

        int detail_width = stacked ? terminal.dimx : terminal.dimx - list_width;
        int detail_height = stacked ? panes_height - list_height : panes_height;
        int detail_text_width = detail_width - 2;
        int detail_text_height = std::max(detail_height - 2, 1);
        Elements detail_lines;
        int value_label_line = -1;
        auto add_wrapped = [&](std::string_view content, Decorator style) {
            for (std::string_view piece : wrap_lines(content, detail_text_width)) {
                detail_lines.push_back(text(std::string(piece)) | style);
            }
        };
        if (rows.empty()) {
            detail_lines.push_back(text(filter.empty() ? "press 'a' to add a secret" : "Esc clears the filter") | dim);
        } else if (row_at(selected).dir) {
            const std::string& folder = row_at(selected).id;
            std::size_t count = 0;
            for (const std::string& key : keys) {
                if (key.compare(0, folder.size(), folder) == 0) ++count;
            }
            detail_lines.push_back(text("folder:") | dim);
            add_wrapped(printable(folder), bold);
            detail_lines.push_back(separator());
            detail_lines.push_back(text(std::to_string(count) + " secret(s)"));
        } else {
            const std::string& key = row_at(selected).id;
            detail_lines.push_back(text("name:") | dim);
            add_wrapped(printable(key), bold);
            auto mapped = marks.env_vars_by_key.find(key);
            if (mapped != marks.env_vars_by_key.end()) {
                detail_lines.push_back(text("env var in " + marks.project + "'s manifest:") | dim);
                for (const std::string& env_var : mapped->second) add_wrapped(env_var, color(Color::Cyan));
            }
            detail_lines.push_back(separator());
            value_label_line = static_cast<int>(detail_lines.size());
            detail_lines.push_back(text("value:") | dim);
            if (revealed) {
                std::string shown_value = printable_value(*revealed);
                add_wrapped(shown_value, nothing);
                zero(shown_value);
            } else {
                detail_lines.push_back(text("••••••••"));
                detail_lines.push_back(text("(Enter or r reveals, c copies)") | dim);
            }
        }
        int detail_line_count = static_cast<int>(detail_lines.size());
        bool detail_overflows = detail_line_count > detail_text_height;
        // A short pane (stacked, a long name, or squeezed by a long message or
        // a resize) would leave a revealed value below the fold.
        if (keep_value_in_view && revealed && value_label_line + 2 > detail_scroll + detail_text_height) {
            detail_scroll = value_label_line;
        }
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
        if (mode == Mode::Normal && keys.empty()) {
            hint_items = {"a add", daemon_state != DaemonState::Ok ? "R retry" : "R reload", "? help  q quit"};
        } else if (mode == Mode::Normal) {
            hint_items = {"j/k move"};
            if (current_key()) {
                hint_items.insert(hint_items.end(), {revealed ? "Enter/r hide" : "Enter/r reveal", "c copy"});
            }
            if (detail_overflows) hint_items.push_back("J/K scroll");
            if (daemon_state != DaemonState::Ok) hint_items.push_back("R retry");
            if (!filter.empty()) hint_items.push_back("Esc clear filter");
            hint_items.insert(hint_items.end(), {"h/l fold", "/ filter", "a add", "e edit", "d delete"});
            if (daemon_state == DaemonState::Ok) hint_items.push_back("R reload");
            hint_items.push_back("? help  q quit");
        } else if (mode == Mode::Filter) {
            hint_items = {"type to narrow", "↑/↓ move", "Enter keep filter", "Esc clear"};
        } else if (mode == Mode::Help) {
            hint_items = {"j/k scroll  any other key closes help"};
        } else if (mode == Mode::Add || mode == Mode::Edit) {
            // fit_hints drops from the second-to-last back, so the reveal toggle goes early.
            bool in_name = mode == Mode::Add && form_field == 0;
            hint_items = {in_name ? "Enter next field" : "Enter save",
                          value_masked ? "Ctrl-R show value" : "Ctrl-R hide value"};
            if (mode == Mode::Add) hint_items.push_back("Tab switch field");
            hint_items.insert(hint_items.end(), {"Ctrl-U/W erase", "Ctrl-A/E line start/end", "Esc cancel"});
        } else {
            hint_items = {"y yes  other keys no"};
        }
        Element hints = text(" " + fit_hints(hint_items, terminal.dimx - 2) + " ") | dim | center;

        Element panes = stacked ? vbox({list_pane, detail_pane}) : hbox({list_pane, detail_pane});
        Element root = vbox({panes | flex, hints, status_bar});
        // A centred modal keeps clear of the hint line and status bar when its
        // height leaves at least this many rows on each side.
        int rows_below_panes = 1 + status_height;

        // The overwrite confirm replaces the form rather than sitting on it: a
        // modal's blank margin would cut through the form's border.
        if (mode == Mode::Add || mode == Mode::Edit) {
            bool adding = mode == Mode::Add;
            // Narrow terminals give the form every column: the value input can't soft-wrap.
            int overlay_width = stacked ? std::max(terminal.dimx - 2, 10) : std::clamp(terminal.dimx - 4, 20, 72);
            Elements lines;
            if (adding) {
                lines.push_back(hbox({text("name:  "), name_input->Render()}));
                std::string name = trim_key_name(add_name);
                if (key_exists(name)) {
                    lines.push_back(text("       exists: saving will ask to overwrite") | color(Color::Yellow));
                }
            } else {
                // Wrapped, not cut: the last segment is what tells keys apart.
                std::string name = printable(current_key().value_or(""));
                const char* label = "name:  ";
                for (std::string_view piece : wrap_lines(name, std::max(overlay_width - 9, 1))) {
                    lines.push_back(hbox({text(label), text(std::string(piece)) | bold}));
                    label = "       ";
                }
            }
            std::optional<std::string> problem = show_form_problem ? form_problem() : std::nullopt;
            int line_rows = static_cast<int>(lines.size()) + (problem ? 1 : 0);
            // 4: the modal's blank margin and the window border.
            int value_rows = std::clamp(terminal.dimy - 2 * rows_below_panes - 4 - line_rows, 1, 8);
            // ponytail: the masked input draws a bullet per character (FTXUI's
            // password mode), so length and line shape show; a fixed placeholder
            // would hide typing feedback. FTXUI draws no glyph (and no bullet) for
            // a tab or other control character, and its Input has no display
            // hook; the detail pane shows them. Long lines scroll sideways with
            // the cursor, which FTXUI keeps centred, so once any line is wider
            // than the input every line shifts and loses its start (FTXUI's
            // Input can't soft-wrap); the detail pane wraps them.
            lines.push_back(hbox({text("value: "), value_input->Render() | size(HEIGHT, LESS_THAN, value_rows)}));
            if (problem) lines.push_back(text("       " + *problem) | color(Color::Red));
            std::string title = adding ? " add secret: env/project/KEY " : " edit secret ";
            // FTXUI's Input shows no sign of the lines scrolled out above or below.
            auto value_lines = std::count(add_value.begin(), add_value.end(), '\n') + 1;
            if (value_lines > value_rows) {
                auto cursor_end = add_value.begin() + std::clamp(value_cursor, 0, static_cast<int>(add_value.size()));
                auto cursor_line = std::count(add_value.begin(), cursor_end, '\n') + 1;
                title += "· line " + std::to_string(cursor_line) + "/" + std::to_string(value_lines) + " ";
            }
            root = dbox({root, modal(window(text(title), vbox(std::move(lines))) | size(WIDTH, EQUAL, overlay_width))});
        }
        if (mode == Mode::ConfirmDelete || mode == Mode::ConfirmOverwrite) {
            std::string name = printable(mode == Mode::ConfirmDelete ? current_key().value_or("")
                                                                     : trim_key_name(add_name));
            std::string verb = mode == Mode::ConfirmDelete ? "Delete '" : "Overwrite '";
            constexpr std::string_view kAsk = "'? [y/N]";
            std::string question = verb + name + std::string(kAsk);
            // Side by side, dimx - 8 keeps a visible segment of the pane borders
            // outside the modal's margin. Stacked, the modal spans the full width
            // like the form, so no pane text shows beside it.
            int question_width = stacked ? std::max(terminal.dimx - 4, 10)
                                         : std::min(text_columns(question), std::max(terminal.dimx - 8, 10));
            // Taller than the room above the hint line (4: the modal's blank margin
            // and the border), the name loses its middle so the [y/N] tail and the
            // hints stay on screen.
            int question_rows = std::max(terminal.dimy - 2 * rows_below_panes - 4, 1);
            if (static_cast<int>(wrap_lines(question, question_width).size()) > question_rows) {
                int fixed_columns = text_columns(verb) + text_columns(kAsk);
                question = verb + ellipsize_middle(name, question_rows * question_width - fixed_columns) +
                           std::string(kAsk);
            }
            Elements question_lines;
            for (std::string_view piece : wrap_lines(question, question_width)) {
                question_lines.push_back(text(std::string(piece)));
            }
            Element dialog = window(text(" confirm "), vbox(std::move(question_lines)));
            if (stacked) dialog |= size(WIDTH, EQUAL, question_width + 2);
            root = dbox({root, modal(std::move(dialog))});
        }
        if (mode == Mode::Help) {
            // Rows are pre-formatted to the overlay width so FTXUI never shrinks the keys column.
            int help_width = std::clamp(terminal.dimx - 4, 10, 76);  // inside the margin and border
            constexpr int kHelpKeysWidth = 20;
            std::vector<std::pair<std::string, bool>> help_text;  // line, is heading
            auto add_section = [&](std::string_view heading) { help_text.emplace_back(heading, true); };
            auto add_row = [&](std::string_view row_keys, std::string_view row_text) {
                int keys_width = row_keys.empty() ? 0 : kHelpKeysWidth;  // a keyless row gets the full width
                for (std::string& line : help_row_lines(row_keys, row_text, keys_width, help_width)) {
                    help_text.emplace_back(std::move(line), false);
                }
            };
            for (const HelpLine& line : kHelp) {
                if (line.keys) {
                    add_row(line.keys, line.text);
                } else {
                    add_section(line.text);
                }
            }
            add_section("daemon");
            add_row("socket", printable(daemon.socket_path()));
            add_row("if it stops", "start it (scripts/service start), then R");
            if (!marks.problem.empty()) {
                add_section("project manifest (refused)");
                add_row("", printable(marks.problem));
            } else if (!marks.project.empty()) {
                add_section("project manifest");
                add_row("◆", "marks keys used by project '" + marks.project + "'");
            }
            // Inside the margin and border, clear of the hint line and status bar.
            int help_height = std::max(terminal.dimy - 4 - 2 * rows_below_panes, 1);
            int help_count = static_cast<int>(help_text.size());
            bool help_overflows = help_count > help_height;
            help_scroll = std::clamp(help_scroll, 0, std::max(0, help_count - help_height));
            int help_last = std::min(help_count, help_scroll + help_height);
            Elements help_lines;
            for (int i = help_scroll; i < help_last; ++i) {
                const auto& [line, heading] = help_text[static_cast<std::size_t>(i)];
                help_lines.push_back(heading ? text(line) | bold : text(line));
            }
            std::string help_title = " keys ";
            if (help_overflows) {
                help_title += std::to_string(help_scroll + 1) + "-" + std::to_string(help_last) + "/" +
                              std::to_string(help_count) + " j/k ";
            }
            root = dbox({root, modal(window(text(help_title), vbox(std::move(help_lines))) |
                                     size(WIDTH, EQUAL, help_width + 2))});
        }
        return root;
    });

    const Event paste_start = Event::Special("\x1b[200~");
    const Event paste_end = Event::Special("\x1b[201~");

    // The ticker posts Event::Custom once a second, or kPasteBurst after a request.
    std::mutex tick_mutex;
    std::condition_variable_any tick_wakeup;
    bool quick_tick_requested = false;
    auto request_quick_tick = [&] {
        {
            std::lock_guard lock(tick_mutex);
            quick_tick_requested = true;
        }
        tick_wakeup.notify_one();
    };

    // No more input came within kPasteBurst: the held key was typed, so it acts.
    auto release_held_key = [&] {
        held_key_since.reset();
        if (held_key_is_tab) {
            if (mode == Mode::Add) form_field = 0;
            return;
        }
        if (mode == Mode::Add) {
            submit_add();
        } else if (mode == Mode::Edit) {
            submit_edit();
        }
        ignore_keys_until = Clock::now() + kAfterSubmitQuiet;
    };

    Component app = CatchEvent(renderer, [&](Event event) -> bool {
        if (event == Event::Custom) {  // the once-a-second tick, or the held key's deadline
            if (held_key_since && Clock::now() - *held_key_since >= kPasteBurst) release_held_key();
            expire();
            return true;
        }
        sync_selection();
        expire();
        if (held_key_since && !event.is_mouse()) {
            bool pasted = Clock::now() - *held_key_since < kPasteBurst &&
                          (event.is_character() || event == Event::Return || event == Event::Tab);
            if (pasted) {
                held_key_since.reset();
                insert_into_value(held_key_is_tab ? "\t" : "\n");
            } else {
                release_held_key();
            }
        }
        bool is_mouse_press = event.is_mouse() && event.mouse().motion == Mouse::Pressed;
        if (event == Event::CtrlC) {  // quit through Exit so the buffers below get zeroed
            screen.Exit();
            return true;
        }
        // The rest of a paste that a held Enter didn't catch must not run as commands.
        if (!event.is_mouse() && Clock::now() < ignore_keys_until) {
            ignore_keys_until = Clock::now() + kAfterSubmitQuiet;
            const std::string ignored = "input right after Enter ignored";
            if (status.empty()) {
                say(ignored);
            } else if (status.find(ignored) == std::string::npos) {
                status += " (" + ignored + ")";
            }
            return true;
        }
        // Any key or click ends the previous message, error or not.
        if (!event.is_mouse() || is_mouse_press) status.clear();

        if (event == Event::CtrlZ) {  // suspending would leave bracketed paste off after fg
            say("Ctrl-Z suspend is off in the TUI; q quits");
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
                say("paste aborted");
            } else if (event.is_character()) {
                paste_buffer += event.character();
            } else if (event == Event::Return) {
                paste_buffer += '\n';
            } else if (event == Event::Tab) {
                paste_buffer += '\t';
            }
            return true;
        }
        if (mode == Mode::Help) {
            bool down = event == Event::Character('j') || event == Event::Character('J') ||
                        event == Event::ArrowDown || event == Event::PageDown ||
                        (event.is_mouse() && event.mouse().button == Mouse::WheelDown);
            bool up = event == Event::Character('k') || event == Event::Character('K') || event == Event::ArrowUp ||
                      event == Event::PageUp || (event.is_mouse() && event.mouse().button == Mouse::WheelUp);
            if (down || up) {
                int step = event == Event::PageDown || event == Event::PageUp ? 10 : 1;
                help_scroll += down ? step : -step;  // the renderer clamps it
            } else if (!event.is_mouse()) {
                mode = Mode::Normal;
            }
            return true;
        }
        if (mode == Mode::Filter) {
            if (event == Event::Return) {
                mode = Mode::Normal;
                // An unbracketed paste's next line must not run as Normal-mode commands.
                ignore_keys_until = Clock::now() + kAfterSubmitQuiet;
            } else if (event == Event::Escape) {
                clear_filter();
                mode = Mode::Normal;
            } else if (event == Event::Backspace) {
                while (!filter.empty()) {
                    char removed = filter.back();
                    filter.pop_back();
                    if ((static_cast<unsigned char>(removed) & 0xC0) != 0x80) break;  // whole code point gone
                }
                apply_filter();
            } else if (event == Event::CtrlU) {
                zero(filter);
                apply_filter();
            } else if (event.is_character()) {
                filter += event.character();
                apply_filter();
            } else {
                return false;  // arrows, PgUp/PgDn, Home/End and the mouse reach the menu
            }
            return true;
        }
        if (mode == Mode::Normal) {
            if (is_mouse_press && event.mouse().button == Mouse::Left) {
                bool on_row = menu->OnEvent(event);
                sync_selection();
                if (on_row && !rows.empty() && row_at(selected).dir) fold(std::nullopt);
                return true;
            }
            if (event == Event::Character('q')) {
                screen.Exit();
                return true;
            }
            if (event == Event::Character('?') || event == Event::F1) {
                mode = Mode::Help;
                help_scroll = 0;
                return true;
            }
            if (event == Event::Character('/')) {
                mode = Mode::Filter;
                return true;
            }
            if (event == Event::Escape) {
                clear_filter();
                return true;
            }
            if (event == Event::Character('R')) {
                reload();
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
            if (event == Event::Character('c')) {
                copy_value();
                return true;
            }
            if (event == Event::Character('r')) {
                toggle_reveal();
                return true;
            }
            if (event == Event::Character('d')) {
                if (need_key("delete")) mode = Mode::ConfirmDelete;
                return true;
            }
            if (event == Event::Return || event == Event::Character(' ')) {
                if (current_key()) {
                    toggle_reveal();
                } else {
                    fold(std::nullopt);
                }
                return true;
            }
            if (event == Event::Character('g') || event == Event::Character('G')) {
                selected = event == Event::Character('g') ? 0 : std::max(static_cast<int>(rows.size()) - 1, 0);
                return true;
            }
            if (event == Event::ArrowLeft || event == Event::Character('h')) {
                bool open_folder = !rows.empty() && row_at(selected).dir && !is_folded(row_at(selected).id);
                if (open_folder && filter.empty()) {
                    fold(false);
                } else {
                    go_parent();
                }
                return true;
            }
            if (event == Event::ArrowRight || event == Event::Character('l')) {
                if (rows.empty() || !row_at(selected).dir) return true;
                bool has_child_row = selected + 1 < static_cast<int>(rows.size()) &&
                                     row_at(selected + 1).depth > row_at(selected).depth;
                if (is_folded(row_at(selected).id)) {
                    fold(true);
                } else if (has_child_row) {
                    ++selected;
                }
                return true;
            }
            if (event == Event::Character('J') || event == Event::Character('K')) {
                detail_scroll += event == Event::Character('J') ? 1 : -1;  // the renderer clamps it
                keep_value_in_view = false;
                return true;
            }
            return false;  // up/down, j/k, PgUp/PgDn, Home/End and the wheel fall through to the menu
        }
        if (mode == Mode::Add || mode == Mode::Edit) {
            if (event == Event::Escape) {
                cancel_form();
                return true;
            }
            if (event == Event::Return) {
                if (mode == Mode::Add && form_field == 0) {
                    form_field = 1;
                } else {
                    // Held back: more input right behind it means a paste, and the Enter was a newline.
                    held_key_since = Clock::now();
                    held_key_is_tab = false;
                    request_quick_tick();
                }
                return true;
            }
            if (event == Event::CtrlR) {
                value_masked = !value_masked;
                return true;
            }
            // Held back like Enter: a pasted tab would otherwise move focus and
            // send the rest of the value into the name.
            if (event == Event::Tab && form_field == 1) {
                held_key_since = Clock::now();
                held_key_is_tab = true;
                request_quick_tick();
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
        // Confirm modes consume every event; only a key answers, so the mouse
        // moving over the terminal can't cancel the question.
        if (event.is_mouse()) return true;
        bool confirmed = event == Event::Character('y') || event == Event::Character('Y');
        if (mode == Mode::ConfirmOverwrite) {
            if (!confirmed || !save_form(trim_key_name(add_name), "updated")) mode = Mode::Add;
            if (!confirmed) say("not saved; edit the name or Esc");
            return true;
        }
        if (confirmed) {
            do_delete();
        } else {
            mode = Mode::Normal;
            say("cancelled");
        }
        return true;
    });

    // Drives the reveal countdown, the auto re-mask, message expiry and the held key.
    std::jthread ticker([&](std::stop_token stop) {
        std::unique_lock lock(tick_mutex);
        while (!stop.stop_requested()) {
            if (tick_wakeup.wait_for(lock, stop, std::chrono::seconds(1), [&] { return quick_tick_requested; })) {
                quick_tick_requested = false;
                tick_wakeup.wait_for(lock, stop, kPasteBurst, [] { return false; });
            }
            if (stop.stop_requested()) return;
            screen.PostEvent(Event::Custom);
        }
    });

    screen.ForceHandleCtrlC(false);
    screen.ForceHandleCtrlZ(false);
    std::cout << "\x1b[?2004h" << std::flush;  // bracketed paste; FTXUI doesn't request it
    screen.Loop(app);
    std::cout << "\x1b[?2004l" << std::flush;
    ticker.request_stop();
    ticker.join();

    remask();
    zero(add_name);
    zero(add_value);
    zero(paste_buffer);
    zero(filter);
    return 0;
}

}  // namespace

int run_tui() {
    if (!::isatty(STDIN_FILENO) || !::isatty(STDOUT_FILENO)) {
        std::fputs("secretov tui: requires a terminal\n", stderr);
        return 1;
    }

    Paths paths = resolve_paths();
    if (::access(paths.token.c_str(), F_OK) != 0) {
        std::fprintf(stderr, "secretov: no API token at %s\n  run 'secretov init' to create the store and token\n",
                     paths.token.c_str());
        return 1;
    }
    try {
        DaemonClient daemon(paths);
        daemon.request("list");  // fail fast if unreachable/unauthorized, before the screen goes fullscreen
        return run_ui(daemon, load_project_marks());
    } catch (const DaemonUnreachable& e) {
        std::fprintf(stderr, "secretov: %s\n", e.what());
        if (e.stage == DaemonUnreachable::Stage::NotRunning) {
            std::fprintf(stderr, "  %s\n", kStartDaemonHint);
        } else if (is_busy(e)) {
            std::fprintf(stderr, "  %s\n", kBusyDaemonHint);
        }
        return 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "secretov: %s\n", e.what());
        if (std::string_view(e.what()) == "invalid token") {
            std::fprintf(stderr, "  %s differs from the token the daemon loaded at start; restart the daemon\n",
                         paths.token.c_str());
        }
        return 1;
    }
}

}  // namespace secretov
