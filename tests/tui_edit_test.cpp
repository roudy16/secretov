#include "tui_edit.hpp"

// Tests must assert even in Release builds (CMakeLists.txt defaults an unset build type to Release).
#undef NDEBUG
#include <cassert>
#include <cstdio>
#include <set>
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
    assert(key_name_error("dev/a\xc2\x85"));  // C1 NEL
    assert(!key_name_error("dev/é"));
    assert(!secretov::has_control_char("plain é"));
    assert(secretov::has_control_char("a\nb"));
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

    text = "ac";
    cursor = 1;
    secretov::insert_at_cursor(text, cursor, "b");
    assert(text == "abc" && cursor == 2);
    cursor = 99;  // out of range: clamped to the end
    secretov::insert_at_cursor(text, cursor, "de");
    assert(text == "abcde" && cursor == 5);

    text = "aé";
    secretov::erase_last_code_point(text);
    assert(text == "a");
    secretov::erase_last_code_point(text);
    assert(text.empty());
    secretov::erase_last_code_point(text);
    assert(text.empty());
}

using secretov::Row;

std::vector<std::string> ids(const std::vector<Row>& rows) {
    std::vector<std::string> row_ids;
    for (const Row& row : rows) row_ids.push_back(row.id);
    return row_ids;
}

void test_tree_rows() {
    const std::vector<std::string> keys = {"TOP", "dev/api/KEY", "dev/api/OTHER", "dev/db/PASS", "prod/X"};
    std::vector<Row> rows;
    std::vector<std::string> labels;

    secretov::build_rows(keys, "", {}, rows, labels);
    assert((ids(rows) == std::vector<std::string>{"TOP", "dev/", "dev/api/", "dev/api/KEY", "dev/api/OTHER", "dev/db/",
                                                  "dev/db/PASS", "prod/", "prod/X"}));
    assert((labels == std::vector<std::string>{"TOP", "dev/", "api/", "KEY", "OTHER", "db/", "PASS", "prod/", "X"}));
    assert(rows[1].dir && rows[1].depth == 0 && rows[3].depth == 2 && !rows[3].dir && rows[0].depth == 0);

    secretov::build_rows(keys, "", {"dev/api/"}, rows, labels);
    assert((ids(rows) == std::vector<std::string>{"TOP", "dev/", "dev/api/", "dev/db/", "dev/db/PASS", "prod/", "prod/X"}));
    secretov::build_rows(keys, "", {"dev/"}, rows, labels);
    assert((ids(rows) == std::vector<std::string>{"TOP", "dev/", "prod/", "prod/X"}));
    assert(labels.size() == rows.size());

    // A filter opens folded folders and keeps only the matching keys' folders.
    secretov::build_rows(keys, "pass", {"dev/"}, rows, labels);
    assert((ids(rows) == std::vector<std::string>{"dev/", "dev/db/", "dev/db/PASS"}));

    secretov::build_rows({"a/\nb"}, "", {}, rows, labels);
    assert(labels.back() == "?b");

    secretov::build_rows(keys, "", {}, rows, labels);
    // Next sibling first, then the previous one, then enclosing folders, then the row above them.
    assert((secretov::delete_landing(rows, 3) ==
            std::vector<std::string>{"dev/api/OTHER", "dev/api/", "dev/", "TOP"}));
    assert((secretov::delete_landing(rows, 4) == std::vector<std::string>{"dev/api/KEY", "dev/api/", "dev/", "dev/api/KEY"}));
    // Last child of the last folder: the folder itself, then the row above it.
    assert((secretov::delete_landing(rows, 8) == std::vector<std::string>{"prod/", "dev/db/PASS"}));
    assert((secretov::delete_landing(rows, 0) == std::vector<std::string>{"dev/"}));
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
    assert(secretov::printable("a\xc2\x9b" "b\xc2\x85") == "a?b?");
    assert(secretov::ellipsize_middle("dev/api/KEY", 20) == "dev/api/KEY");
    assert(secretov::ellipsize_middle("dev/api/LONGKEY", 9) == "dev/…GKEY");
    assert(secretov::ellipsize_middle("dev/é/x", 3) == "d…x");
    assert(secretov::printable_value("a\tb\r\nc\x7f\xc2\x85" "d é") == "a→b?\nc??d é");
}

}  // namespace

int main() {
    test_key_names();
    test_folder_prefix();
    test_readline_edits();
    test_layout_text();
    test_filter_and_copy();
    test_wrapping_and_printable();
    test_tree_rows();
    std::printf("OK\n");
    return 0;
}
