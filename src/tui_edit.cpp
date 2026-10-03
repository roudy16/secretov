#include "tui_edit.hpp"

#include <sodium.h>

#include <algorithm>
#include <cctype>

namespace secretov {

namespace {

bool is_space(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'; }

// Ctrl-W stops at '/' too, so it peels one path segment off a key name.
bool is_word_separator(char c) { return is_space(c) || c == '/'; }

bool starts_code_point(char c) { return (static_cast<unsigned char>(c) & 0xC0) != 0x80; }

// Byte length of the longest prefix of `text` that fits in `width` columns.
std::size_t prefix_bytes(std::string_view text, int width) {
    int columns = 0;
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (starts_code_point(text[i]) && columns++ == width) return i;
    }
    return text.size();
}

std::size_t clamped(const std::string& text, int cursor) {
    return static_cast<std::size_t>(std::clamp(cursor, 0, static_cast<int>(text.size())));
}

}  // namespace

std::string trim_key_name(std::string_view name) {
    std::size_t first = 0;
    std::size_t last = name.size();
    while (first < last && is_space(name[first])) ++first;
    while (last > first && is_space(name[last - 1])) --last;
    return std::string(name.substr(first, last - first));
}

std::optional<std::string> key_name_error(std::string_view name) {
    if (name.empty()) return "name required";
    for (char c : name) {
        auto byte = static_cast<unsigned char>(c);
        if (byte < 0x20 || byte == 0x7f) return "name can't contain control characters";
    }
    if (name.front() == '/') return "name can't start with '/'";
    if (name.back() == '/') return "name can't end with '/' (add a KEY after the folder)";
    if (name.find("//") != std::string_view::npos) return "name can't have an empty segment ('//')";
    return std::nullopt;
}

std::string folder_prefix(std::string_view row_id) {
    std::size_t last_slash = row_id.rfind('/');
    if (last_slash == std::string_view::npos) return "";
    return std::string(row_id.substr(0, last_slash + 1));
}

bool contains_ignore_case(std::string_view text, std::string_view needle) {
    if (needle.empty()) return true;
    auto same = [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
    };
    return std::search(text.begin(), text.end(), needle.begin(), needle.end(), same) != text.end();
}

std::string osc52_copy_sequence(std::string_view value) {
    constexpr std::string_view kStart = "\x1b]52;c;";
    std::size_t encoded_size = sodium_base64_ENCODED_LEN(value.size(), sodium_base64_VARIANT_ORIGINAL);  // with NUL
    std::string sequence(kStart.size() + encoded_size, '\0');
    std::copy(kStart.begin(), kStart.end(), sequence.begin());
    sodium_bin2base64(sequence.data() + kStart.size(), encoded_size,
                      reinterpret_cast<const unsigned char*>(value.data()), value.size(),
                      sodium_base64_VARIANT_ORIGINAL);
    sequence.back() = '\a';  // in place of the NUL
    return sequence;
}

int line_start(const std::string& text, int cursor) {
    std::size_t position = clamped(text, cursor);
    while (position > 0 && text[position - 1] != '\n') --position;
    return static_cast<int>(position);
}

int line_end(const std::string& text, int cursor) {
    std::size_t position = clamped(text, cursor);
    while (position < text.size() && text[position] != '\n') ++position;
    return static_cast<int>(position);
}

void erase_to_line_start(std::string& text, int& cursor) {
    std::size_t end = clamped(text, cursor);
    std::size_t start = static_cast<std::size_t>(line_start(text, cursor));
    text.erase(start, end - start);
    cursor = static_cast<int>(start);
}

void erase_word_before(std::string& text, int& cursor) {
    std::size_t end = clamped(text, cursor);
    std::size_t start = end;
    while (start > 0 && is_word_separator(text[start - 1])) --start;
    while (start > 0 && !is_word_separator(text[start - 1])) --start;
    text.erase(start, end - start);
    cursor = static_cast<int>(start);
}

int text_columns(std::string_view text) {
    return static_cast<int>(std::count_if(text.begin(), text.end(), starts_code_point));
}

std::string ellipsize(std::string_view text, int width) {
    if (text_columns(text) <= width) return std::string(text);
    if (width <= 0) return "";
    return std::string(text.substr(0, prefix_bytes(text, width - 1))) + "…";
}

std::vector<std::string_view> wrap_lines(std::string_view text, int width) {
    width = std::max(width, 1);
    std::vector<std::string_view> pieces;
    std::size_t line_begin = 0;
    while (true) {
        std::size_t newline = text.find('\n', line_begin);
        std::string_view line = text.substr(line_begin, newline == std::string_view::npos ? newline : newline - line_begin);
        do {
            std::size_t piece = prefix_bytes(line, width);
            pieces.push_back(line.substr(0, piece));
            line.remove_prefix(piece);
        } while (!line.empty());
        if (newline == std::string_view::npos) return pieces;
        line_begin = newline + 1;
    }
}

std::vector<std::string> word_wrap(std::string_view text, int width) {
    width = std::max(width, 1);
    std::vector<std::string> lines;
    std::string line;
    std::size_t position = 0;
    while (position < text.size()) {
        std::size_t space = std::min(text.find(' ', position), text.size());
        std::string_view word = text.substr(position, space - position);
        position = space + 1;
        while (!word.empty()) {
            int needed = text_columns(line) + (line.empty() ? 0 : 1) + text_columns(word);
            if (needed <= width) {
                if (!line.empty()) line += ' ';
                line += word;
                break;
            }
            if (!line.empty()) {
                lines.push_back(std::move(line));
                line.clear();
                continue;
            }
            std::size_t piece = prefix_bytes(word, width);
            lines.emplace_back(word.substr(0, piece));
            word.remove_prefix(piece);
        }
    }
    if (!line.empty() || lines.empty()) lines.push_back(std::move(line));
    return lines;
}

std::vector<std::string> help_row_lines(std::string_view keys, std::string_view text, int keys_width, int width) {
    constexpr int kMinTextColumns = 16;
    std::vector<std::string> lines;
    int text_width = width - 2 - keys_width;
    if (text_width >= kMinTextColumns) {
        std::string key_cell = "  " + std::string(keys);
        int padding = keys.empty() ? keys_width : std::max(keys_width - text_columns(keys), 1);
        key_cell.append(static_cast<std::size_t>(padding), ' ');
        std::string indent(static_cast<std::size_t>(2 + keys_width), ' ');
        for (const std::string& piece : word_wrap(text, text_width)) {
            lines.push_back((lines.empty() ? key_cell : indent) + piece);
        }
        return lines;
    }
    if (!keys.empty()) lines.push_back("  " + ellipsize(keys, width - 2));
    for (const std::string& piece : word_wrap(text, width - 4)) lines.push_back("    " + piece);
    return lines;
}

std::string printable(std::string_view text) {
    std::string shown(text);
    for (char& c : shown) {
        auto byte = static_cast<unsigned char>(c);
        if (byte < 0x20 || byte == 0x7f) c = '?';
    }
    return shown;
}

std::string fit_hints(const std::vector<std::string>& hints, int width) {
    std::vector<std::string> kept = hints;
    auto joined = [&] {
        std::string line;
        for (const std::string& hint : kept) line += (line.empty() ? "" : "  ") + hint;
        return line;
    };
    while (kept.size() > 1 && text_columns(joined()) > width) kept.erase(kept.end() - 2);
    return joined();
}

}  // namespace secretov
