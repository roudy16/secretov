#include "manifest.hpp"

#include <sys/stat.h>

// Tests must assert even in Release builds (FTXUI's CMake defaults to Release).
#undef NDEBUG
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>

using namespace secretov;

namespace {

std::string g_dir;

template <typename F>
bool throws_with(F&& fn, const char* needle) {
    try {
        fn();
    } catch (const std::runtime_error& e) {
        if (std::strstr(e.what(), needle) != nullptr) return true;
        std::fprintf(stderr, "unexpected message: %s\n", e.what());
    }
    return false;
}

const std::string kSample =
    "version: \"1\"\n"
    "name: flows-admin\n"
    "default_env: dev\n"
    "env:\n"
    "  dev:\n"
    "    secrets:\n"
    "      # primary database\n"
    "      database-url:\n"
    "        env_var_name: DATABASE_URL\n"
    "      openai-key:\n"
    "        key: shared/flows-admin/openai-key\n"
    "        env_var_name: OPENAI_API_KEY\n"
    "  # production\n"
    "  prod:\n"
    "    secrets: {}\n";

void test_scoped_key() {
    assert(scoped_key("dev", "p", "K") == "dev/p/K");
    assert(scope_prefix("dev", "p") == "dev/p/");
    assert(throws_with([] { scoped_key("de/v", "p", "K"); }, "environment"));
    assert(throws_with([] { scoped_key("dev", "", "K"); }, "project"));
}

void test_dotenv() {
    KeyValues kv = parse_dotenv(
        "# comment\n"
        "\n"
        "export A=1\n"
        "B = two words # trailing\n"
        "C=\"quoted # not comment\\n\"\n"
        "D='single \"inner\"'\r\n"
        "E=\n");
    assert(kv.size() == 5);
    assert(kv[0].first == "A" && kv[0].second == "1");
    assert(kv[1].first == "B" && kv[1].second == "two words");
    assert(kv[2].second == "quoted # not comment\n");
    assert(kv[3].second == "single \"inner\"");
    assert(kv[4].second.empty());
    assert(throws_with([] { parse_dotenv("NOEQUALS\n"); }, "expected KEY=VALUE"));
    assert(throws_with([] { parse_dotenv("1BAD=x\n"); }, "invalid key"));
    assert(throws_with([] { parse_dotenv("Q=\"open\n"); }, "unterminated"));
    assert(throws_with([] { parse_dotenv("Q=\"a\" b\n"); }, "after closing quote"));
}

void test_parse_manifest() {
    Manifest m = parse_manifest(kSample, "t");
    assert(m.project == "flows-admin");
    assert(m.default_env && *m.default_env == "dev");
    const auto& dev = m.envs.at("dev");
    assert(dev.size() == 2);
    assert(dev[0].name == "database-url" && dev[0].key == "dev/flows-admin/database-url" &&
           dev[0].env_var == "DATABASE_URL");
    assert(dev[1].key == "shared/flows-admin/openai-key" && dev[1].env_var == "OPENAI_API_KEY");
    assert(m.envs.at("prod").empty());

    assert(throws_with([] { parse_manifest("env: {}\n", "t"); }, "missing 'name'"));
    assert(throws_with([] { parse_manifest("name: x\nenv:\n  dev:\n    secrets:\n      a: {}\n", "t"); },
                       "missing env_var_name"));
    assert(throws_with(
        [] { parse_manifest("name: x\nenv:\n  dev:\n    secrets:\n      a:\n        env_var_name: 1BAD\n", "t"); },
        "not a valid environment variable"));
    assert(throws_with([] { parse_manifest("name: x\nenv: [a]\n", "t"); }, "'env' must be a mapping"));
}

void test_insert_preserves_text() {
    std::string out = manifest_with_entries(kSample, "flows-admin", "dev", {{"REDIS_URL", "REDIS_URL"}});
    // Entry lands inside dev, after the last dev entry and before prod's comment.
    std::size_t prod_comment = kSample.find("  # production\n");
    assert(out.compare(0, prod_comment, kSample, 0, prod_comment) == 0);
    assert(out.substr(prod_comment) ==
           "      REDIS_URL:\n        env_var_name: REDIS_URL\n" + kSample.substr(prod_comment));
    // Idempotent: an existing entry is not duplicated.
    assert(manifest_with_entries(out, "flows-admin", "dev", {{"REDIS_URL", "REDIS_URL"}}) == out);
    Manifest m = parse_manifest(out, "t");
    assert(m.envs.at("dev").size() == 3 && m.envs.at("dev")[2].key == "dev/flows-admin/REDIS_URL");
}

void test_insert_new_env_block() {
    std::string out = manifest_with_entries(kSample, "flows-admin", "stg", {{"X", "X"}});
    assert(out.find("  stg:\n    secrets:\n      X:\n        env_var_name: X\n") != std::string::npos);
    assert(parse_manifest(out, "t").envs.at("stg")[0].key == "stg/flows-admin/X");
}

void test_insert_rejects_inline_and_mismatch() {
    assert(throws_with([] { manifest_with_entries(kSample, "flows-admin", "prod", {{"X", "X"}}); },
                       "inline value"));
    assert(throws_with([] { manifest_with_entries(kSample, "other", "dev", {{"X", "X"}}); },
                       "names project"));
}

void test_insert_fresh_and_four_space() {
    assert(manifest_with_entries("", "newproj", "dev", {{"A", "A"}}) ==
           "version: \"1\"\nname: newproj\nenv:\n  dev:\n    secrets:\n      A:\n        env_var_name: A\n");
    std::string four =
        "name: p\nenv:\n    dev:\n        secrets:\n            A:\n                env_var_name: A\n";
    std::string out = manifest_with_entries(four, "p", "dev", {{"B", "B"}});
    assert(out == four + "            B:\n                env_var_name: B\n");
    // No env block at all: one gets appended.
    std::string bare = "name: p\n";
    assert(manifest_with_entries(bare, "p", "dev", {{"A", "A"}}) ==
           "name: p\nenv:\n  dev:\n    secrets:\n      A:\n        env_var_name: A\n");
}

void test_registry() {
    std::string path = g_dir + "/projects.yaml";
    {
        std::ofstream f(path);
        f << "projects:\n  demo:\n    root: \"${HOME}\"\n  broken:\n    root: /nonexistent/xyz\n";
    }
    std::optional<std::string> root = registry_project_root(path, "demo");
    assert(root && *root == std::getenv("HOME"));
    assert(!registry_project_root(path, "nope"));
    assert(!registry_project_root(g_dir + "/missing.yaml", "demo"));
    assert(throws_with([&] { registry_project_root(path, "broken"); }, "project root not found"));
}

void test_find_manifest_upward() {
    std::string nested = g_dir + "/a/b";
    assert(::mkdir((g_dir + "/a").c_str(), 0700) == 0);
    assert(::mkdir(nested.c_str(), 0700) == 0);
    assert(!find_manifest_upward(nested));
    { std::ofstream f(g_dir + "/a/.secretov.yaml"); f << "name: a\n"; }
    std::optional<std::string> found = find_manifest_upward(nested);
    assert(found && *found == g_dir + "/a/.secretov.yaml");
}


void test_vars() {
    const std::string text =
        "version: \"1\"\n"
        "name: proj\n"
        "env:\n"
        "  dev:\n"
        "    vars:\n"
        "      LOG_LEVEL: debug\n"
        "      API_URL: https://dev.example.com\n"
        "      PORT: 8080\n"
        "      EMPTY: \"\"\n"
        "    secrets:\n"
        "      DB_URL:\n"
        "        env_var_name: DB_URL\n";
    Manifest m = parse_manifest(text, "test");
    const KeyValues& v = m.vars.at("dev");
    assert(v.size() == 4);
    assert(v[0].first == "LOG_LEVEL" && v[0].second == "debug");        // file order kept
    assert(v[1].second == "https://dev.example.com");
    assert(v[2].second == "8080");                                      // YAML scalars stringified
    assert(v[3].second.empty());
    assert(m.envs.at("dev").size() == 1);                               // secrets unaffected

    // An env with vars and no secrets block is legal.
    Manifest only = parse_manifest(
        "name: proj\nenv:\n  dev:\n    vars:\n      A: b\n", "test");
    assert(only.vars.at("dev").size() == 1);
    assert(only.envs.at("dev").empty());

    // No vars block yields an empty list, not a missing env.
    Manifest none = parse_manifest(
        "name: proj\nenv:\n  dev:\n    secrets:\n      K:\n        env_var_name: K\n", "test");
    assert(none.vars.at("dev").empty());

    // A name defined in both vars and secrets has no sane precedence.
    assert(throws_with(
        [] {
            parse_manifest("name: proj\nenv:\n  dev:\n    vars:\n      DUP: x\n"
                           "    secrets:\n      whatever:\n        env_var_name: DUP\n",
                           "test");
        },
        "is set in both vars and secrets"));

    assert(throws_with(
        [] { parse_manifest("name: proj\nenv:\n  dev:\n    vars:\n      bad-name: x\n", "test"); },
        "not a valid environment variable name"));

    assert(throws_with(
        [] { parse_manifest("name: proj\nenv:\n  dev:\n    vars:\n      NESTED:\n        a: b\n", "test"); },
        "must be a scalar value"));

    assert(throws_with(
        [] { parse_manifest("name: proj\nenv:\n  dev:\n    vars: notamap\n", "test"); },
        "vars must be a mapping"));
}

// import edits the secrets: block textually; a sibling vars: block must survive.
void test_insert_preserves_vars_block() {
    const std::string text =
        "version: \"1\"\n"
        "name: proj\n"
        "env:\n"
        "  dev:\n"
        "    vars:\n"
        "      LOG_LEVEL: debug   # keep this comment\n"
        "    secrets:\n"
        "      EXISTING:\n"
        "        env_var_name: EXISTING\n";
    std::string out = manifest_with_entries(text, "proj", "dev", {{"ADDED", "ADDED"}});
    assert(out.find("LOG_LEVEL: debug   # keep this comment") != std::string::npos);
    Manifest m = parse_manifest(out, "test");
    assert(m.vars.at("dev").size() == 1);
    assert(m.vars.at("dev")[0].second == "debug");
    assert(m.envs.at("dev").size() == 2);
}
}  // namespace

int main() {
    char tmpl[] = "/tmp/secretov_manifest_test_XXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir) {
        std::perror("mkdtemp");
        return 1;
    }
    g_dir = dir;

    test_scoped_key();
    test_dotenv();
    test_parse_manifest();
    test_insert_preserves_text();
    test_insert_new_env_block();
    test_insert_rejects_inline_and_mismatch();
    test_insert_fresh_and_four_space();
    test_vars();
    test_insert_preserves_vars_block();
    test_registry();
    test_find_manifest_upward();

    std::printf("OK\n");
    return 0;
}
