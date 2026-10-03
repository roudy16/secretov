#pragma once

// FTXUI-free text helpers behind the TUI's add/edit forms, kept apart from
// tui.cpp so tests can link them without FTXUI. Cursors are byte offsets
// into the edited string, as FTXUI's Input keeps them.

#include <optional>
#include <string>
#include <string_view>

namespace secretov {

// `name` without surrounding whitespace.
std::string trim_key_name(std::string_view name);

// Why a (trimmed) key name is unusable, or nullopt if it is fine.
std::optional<std::string> key_name_error(std::string_view name);

// Folder path an add should start from: "dev/api/" for row "dev/api/" or
// key "dev/api/KEY"; "" for a top-level key.
std::string folder_prefix(std::string_view row_id);

// Readline-style edits on the line holding the cursor.
void erase_to_line_start(std::string& text, int& cursor);  // Ctrl-U
void erase_word_before(std::string& text, int& cursor);    // Ctrl-W
int line_start(const std::string& text, int cursor);        // Ctrl-A
int line_end(const std::string& text, int cursor);          // Ctrl-E

}  // namespace secretov
