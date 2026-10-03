#pragma once

// FTXUI-free text helpers behind the TUI's forms and layout, kept apart from
// tui.cpp so tests can link them without FTXUI. Cursors are byte offsets
// into the edited string, as FTXUI's Input keeps them.

#include <optional>
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

// `text` split at newlines, then each line cut into pieces of at most `width`
// columns. Views into `text`, so wrapping a revealed value copies nothing.
std::vector<std::string_view> wrap_lines(std::string_view text, int width);

// `hints` joined by two spaces, dropping hints before the last one (from the
// back) until the line fits `width`; the last hint is always kept.
std::string fit_hints(const std::vector<std::string>& hints, int width);

}  // namespace secretov
