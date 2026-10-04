#pragma once

// FTXUI-free text helpers behind the TUI's forms and layout, kept apart from
// tui.cpp so tests can link them without FTXUI. Cursors are byte offsets
// into the edited string, as FTXUI's Input keeps them.

#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace secretov {

// `name` without surrounding whitespace.
std::string trim_key_name(std::string_view name);

// Why a (trimmed) key name is unusable, or nullopt if it is fine.
std::optional<std::string> key_name_error(std::string_view name);

// Folder path an add should start from: "dev/api/" for row "dev/api/" or
// key "dev/api/KEY"; "" for a top-level key.
std::string folder_prefix(std::string_view row_id);

// Whether `text` contains `needle`, ASCII letters compared case-insensitively.
bool contains_ignore_case(std::string_view text, std::string_view needle);

// The OSC 52 escape that asks the terminal to put `value` on the clipboard
// (base64, BEL-terminated). It encodes the secret, so the caller zeroes it.
std::string osc52_copy_sequence(std::string_view value);

// Whether `text` holds a control character: C0, DEL or C1.
bool has_control_char(std::string_view text);

// Inserts `inserted` at `cursor` (clamped into `text`) and moves the cursor past it.
void insert_at_cursor(std::string& text, int& cursor, std::string_view inserted);

// Drops the last UTF-8 code point of `text` (Backspace at its end).
void erase_last_code_point(std::string& text);

// Readline-style edits on the line holding the cursor.
void erase_to_line_start(std::string& text, int& cursor);  // Ctrl-U
void erase_word_before(std::string& text, int& cursor);    // Ctrl-W
int line_start(const std::string& text, int cursor);        // Ctrl-A
int line_end(const std::string& text, int cursor);          // Ctrl-E

// Terminal columns `text` takes, one per UTF-8 code point.
// ponytail: wide glyphs (CJK, emoji) count as one column; a wcwidth table if names use them.
int text_columns(std::string_view text);

// `text` cut to at most `width` columns, ending in "…" when something was cut.
std::string ellipsize(std::string_view text, int width);

// `text` cut to at most `width` columns by replacing its middle with "…",
// so both ends (a key's scope and its last segment) stay visible.
std::string ellipsize_middle(std::string_view text, int width);

// `text` split at newlines, then each line cut into pieces of at most `width`
// columns. Views into `text`, so wrapping a revealed value copies nothing.
std::vector<std::string_view> wrap_lines(std::string_view text, int width);

// `text` split at spaces into lines of at most `width` columns; a word wider
// than `width` is cut. Runs of spaces collapse. Always at least one line.
std::vector<std::string> word_wrap(std::string_view text, int width);

// A help row fitted to `width` columns: two spaces, `keys` padded to
// `keys_width`, then `text` word-wrapped beside them. When that leaves the
// text under 16 columns, the keys (if any) take a line of their own instead.
std::vector<std::string> help_row_lines(std::string_view keys, std::string_view text, int keys_width, int width);

// `text` with each control character (C0, DEL, C1) shown as '?'. FTXUI drops most of
// them when drawing but keeps '\n' as a line break, so a key name holding one
// would break the row; and widths must count what is drawn.
std::string printable(std::string_view text);

// A revealed value as the detail pane draws it: newlines kept, a tab shown as
// '→' and any other control character (C0, DEL, C1) as '?', which FTXUI would
// otherwise draw as nothing. The result holds the secret: the caller zeroes it.
std::string printable_value(std::string_view value);

// `hints` joined by two spaces, dropping hints before the last one (from the
// back) until the line fits `width`; the last hint is always kept.
std::string fit_hints(const std::vector<std::string>& hints, int width);

// One visible line of the key tree: a folder ("dev/proj/") or a secret.
struct Row {
    std::string id;  // full key, or folder prefix ending in '/'
    bool dir;
    int depth;
};

// The visible tree rows for sorted `keys`: those containing `filter` (any
// case), under folders not in `collapsed` (ignored while a filter is set).
// `labels` gets each row's last path segment, printable, parallel to `rows`;
// both are cleared first.
void build_rows(const std::vector<std::string>& keys, std::string_view filter, const std::set<std::string>& collapsed,
                std::vector<Row>& rows, std::vector<std::string>& labels);

// Ids to select after deleting rows[selected], best first: the next sibling,
// else the previous one, else the enclosing folders innermost first, else the
// row above all of them (for when every enclosing folder was emptied).
std::vector<std::string> delete_landing(const std::vector<Row>& rows, int selected);

}  // namespace secretov
