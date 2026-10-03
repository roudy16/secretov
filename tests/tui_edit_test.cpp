#include "tui_edit.hpp"

// Tests must assert even in Release builds (FTXUI's CMake defaults to Release).
#undef NDEBUG
#include <cassert>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

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

void test_layout_text() {
    using secretov::ellipsize;
    using secretov::wrap_lines;
    using View = std::vector<std::string_view>;
    assert(secretov::text_columns("a·b…") == 4);
    assert(ellipsize("staging", 7) == "staging");
    assert(ellipsize("staging", 4) == "sta…");
    assert(ellipsize("ab·cd", 4) == "ab·…");
    assert(ellipsize("staging", 1) == "…");
    assert(ellipsize("staging", 0).empty());

    assert(wrap_lines("abcdefg", 3) == (View{"abc", "def", "g"}));
    assert(wrap_lines("abc", 3) == (View{"abc"}));
    assert(wrap_lines("", 3) == (View{""}));
    assert(wrap_lines("ab\n\nabcd\n", 3) == (View{"ab", "", "abc", "d", ""}));
    assert(wrap_lines("··", 1) == (View{"·", "·"}));

    std::vector<std::string> hints = {"j/k move", "a add", "q quit"};
    assert(secretov::fit_hints(hints, 80) == "j/k move  a add  q quit");
    assert(secretov::fit_hints(hints, 18) == "j/k move  q quit");
    assert(secretov::fit_hints(hints, 3) == "q quit");
}

void test_filter_and_copy() {
    using secretov::contains_ignore_case;
    assert(contains_ignore_case("dev/api/STRIPE_KEY", "stripe"));
    assert(contains_ignore_case("dev/api/STRIPE_KEY", "API/s"));
    assert(contains_ignore_case("anything", ""));
    assert(contains_ignore_case("", ""));
    assert(!contains_ignore_case("dev/api", "prod"));
    assert(!contains_ignore_case("ab", "abc"));

    assert(secretov::osc52_copy_sequence("hi") == "\x1b]52;c;aGk=\a");
    assert(secretov::osc52_copy_sequence("") == "\x1b]52;c;\a");
    assert(secretov::osc52_copy_sequence("a\nb") == "\x1b]52;c;YQpi\a");
}

void test_wrapping_and_printable() {
    using V = std::vector<std::string>;
    assert(secretov::word_wrap("fold or go to parent", 10) == (V{"fold or go", "to parent"}));
    assert(secretov::word_wrap("abcdefghij k", 4) == (V{"abcd", "efgh", "ij k"}));
    assert(secretov::word_wrap("a  b", 10) == (V{"a b"}));
    assert(secretov::word_wrap("", 5) == (V{""}));

    assert(secretov::help_row_lines("c", "copy the value now", 4, 22) == (V{"  c   copy the value", "      now"}));
    assert(secretov::help_row_lines("", "aaaa bbbb cccc dddd", 0, 20) == (V{"  aaaa bbbb cccc", "  dddd"}));
    // Too narrow for a text column: the keys get their own line.
    assert(secretov::help_row_lines("Ctrl-U", "erase all", 20, 30) == (V{"  Ctrl-U", "    erase all"}));

    assert(secretov::printable("dev/NL\nKEY\x1b[2J\x7f") == "dev/NL?KEY?[2J?");
    assert(secretov::printable("ok/é") == "ok/é");
}

}  // namespace

int main() {
    test_key_names();
    test_folder_prefix();
    test_readline_edits();
    test_layout_text();
    test_filter_and_copy();
    test_wrapping_and_printable();
    std::printf("OK\n");
    return 0;
}
