#pragma once

#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

namespace secretov {

struct Request {
    std::string token;
    std::string op;
    std::string key;
    std::string value;
};

inline std::optional<Request> parse_request(const std::string& line) {
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(line);
    } catch (const nlohmann::json::parse_error&) {
        return std::nullopt;
    }
    if (!j.is_object() || !j.contains("token") || !j.contains("op")) {
        return std::nullopt;
    }

    Request req;
    try {
        req.token = j.at("token").get<std::string>();
        req.op = j.at("op").get<std::string>();
        req.key = j.value("key", std::string{});
        req.value = j.value("value", std::string{});
    } catch (const nlohmann::json::exception&) {
        return std::nullopt;
    }
    return req;
}

inline std::string ok_response() {
    return nlohmann::json{{"ok", true}}.dump();
}

inline std::string ok_value(const std::string& value) {
    return nlohmann::json{{"ok", true}, {"value", value}}.dump();
}

inline std::string ok_keys(const std::vector<std::string>& keys) {
    return nlohmann::json{{"ok", true}, {"keys", keys}}.dump();
}

inline std::string error_response(const std::string& msg) {
    return nlohmann::json{{"ok", false}, {"error", msg}}.dump();
}

}  // namespace secretov
