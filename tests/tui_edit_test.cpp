#include "tui_edit.hpp"

// Tests must assert even in Release builds (FTXUI's CMake defaults to Release).
#undef NDEBUG
#include <cassert>
#include <cstdio>
#include <string>

namespace {

using secretov::key_name_error;

void test_key_names() {
    assert(secretov::trim_key_name("  dev/api/KEY \t") == "dev/api/KEY");
    assert(secretov::trim_key_name(" \t ").empty());
    assert(!key_name_error("dev/api/KEY"));
    assert(!key_name_error("toplevel"));
    assert(*key_name_error("") == "name required");
    assert(key_name_error("/dev/KEY"));
    assert(key_name_error("dev/api/"));
    assert(key_name_error("dev//KEY"));
    assert(key_name_error("dev/a\tb"));
    assert(key_name_error(std::string("dev/a\x7f", 6)));
}

void test_folder_prefix() {
    assert(secretov::folder_prefix("dev/api/") == "dev/api/");
    assert(secretov::folder_prefix("dev/api/KEY") == "dev/api/");
    assert(secretov::folder_prefix("toplevel").empty());
}

void test_readline_edits() {
    std::string text = "dev/api/KEY";
    int cursor = static_cast<int>(text.size());
    secretov::erase_word_before(text, cursor);
    assert(text == "dev/api/" && cursor == 8);
    secretov::erase_word_before(text, cursor);
    assert(text == "dev/" && cursor == 4);

    text = "one two  three";
    cursor = 7;  // after "two"
    secretov::erase_word_before(text, cursor);
    assert(text == "one   three" && cursor == 4);

    text = "first\nsecond";
    cursor = 9;  // "sec|ond"
    assert(secretov::line_start(text, cursor) == 6);
    assert(secretov::line_end(text, cursor) == 12);
    assert(secretov::line_end(text, 2) == 5);
    secretov::erase_to_line_start(text, cursor);
    assert(text == "first\nond" && cursor == 6);

    cursor = 0;
    secretov::erase_word_before(text, cursor);
    secretov::erase_to_line_start(text, cursor);
    assert(text == "first\nond" && cursor == 0);
}

}  // namespace

int main() {
    test_key_names();
    test_folder_prefix();
    test_readline_edits();
    std::printf("OK\n");
    return 0;
}
