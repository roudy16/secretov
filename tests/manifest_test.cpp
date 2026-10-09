#include "manifest.hpp"

#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

// Tests must assert even in Release builds (CMakeLists.txt defaults an unset build type to Release).
#undef NDEBUG
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

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
    std::ostringstream warnings;
    KeyValues kv = parse_dotenv(
        "# comment\n"
        "\n"
        "export A=1\n"
        "B = two words # trailing\n"
        "C=\"quoted # not comment\\n\"\n"
        "D='single \"inner\"'\r\n"
        "E=\n",
        warnings);
    assert(kv.size() == 5);
    assert(warnings.str().find("line 4") != std::string::npos && warnings.str().find("'B'") != std::string::npos);
    assert(kv[0].first == "A" && kv[0].second == "1");
    assert(kv[1].first == "B" && kv[1].second == "two words");
    assert(kv[2].second == "quoted # not comment\n");
    assert(kv[3].second == "single \"inner\"");
    assert(kv[4].second.empty());
    assert(throws_with([] { parse_dotenv("NOEQUALS\n"); }, "expected KEY=VALUE"));
    assert(throws_with([] { parse_dotenv("1BAD=x\n"); }, "invalid key"));
    assert(throws_with([] { parse_dotenv("Q=\"open\n"); }, "unterminated"));
    assert(throws_with([] { parse_dotenv("Q=\"a\" b\n"); }, "after closing quote"));

    KeyValues escapes = parse_dotenv("T=\"a\\tb\\rc\\\\d\\\"e\"\n");
    assert(escapes[0].second == "a\tb\rc\\d\"e");
    assert(throws_with([] { parse_dotenv("T=\"a\\qb\"\n"); }, "unsupported escape '\\q'"));
    assert(throws_with([] { parse_dotenv("A=1\nB=2\nA=3\n"); }, "line 3: duplicate key 'A' (first set on line 1)"));
}

void test_parse_manifest() {
    Manifest m = parse_manifest(kSample, "t");
    assert(m.project == "flows-admin");
    assert(m.default_env && *m.default_env == "dev");
    const auto& dev = m.envs.at("dev");
    assert(dev.size() == 2);
    assert(dev[0].name == "database-url" && dev[0].path == "dev/flows-admin/database-url" &&
           dev[0].env_var == "DATABASE_URL");
    assert(dev[1].path == "shared/flows-admin/openai-key" && dev[1].env_var == "OPENAI_API_KEY");
    assert(m.envs.at("prod").empty());
    // Existing entries parse as local text entries with no field or location.
    assert(m.backend.type == BackendType::Local && m.backend.location.empty());
    assert(dev[0].kind == EntryKind::Text && dev[0].field.empty() && dev[0].location.empty());

    assert(throws_with([] { parse_manifest("env: {}\n", "t"); }, "missing 'name'"));
    assert(throws_with([] { parse_manifest("name: x\nenv:\n  dev:\n    secrets:\n      a: {}\n", "t"); },
                       "missing env_var_name"));
    assert(throws_with(
        [] { parse_manifest("name: x\nenv:\n  dev:\n    secrets:\n      a:\n        env_var_name: 1BAD\n", "t"); },
        "not a valid environment variable"));
    assert(throws_with([] { parse_manifest("name: x\nenv: [a]\n", "t"); }, "'env' must be a mapping"));
    // yaml-cpp errors from node access keep the manifest path.
    assert(throws_with([] { parse_manifest("name: x\nenv:\n  [a]: {}\n", "t"); }, "manifest 't': "));
    assert(throws_with([] { parse_manifest("name: x\nenv:\n  dev:\n    vars:\n      [A]: b\n", "t"); },
                       "manifest 't': "));
    assert(throws_with(
        [] { parse_manifest("name: x\nenv:\n  dev:\n    secrets:\n      a:\n        env_var_name: A\n        key: [k]\n", "t"); },
        "secret 'a' (env dev) key must be a string"));
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
    assert(m.envs.at("dev").size() == 3 && m.envs.at("dev")[2].path == "dev/flows-admin/REDIS_URL");
}

void test_insert_new_env_block() {
    std::string out = manifest_with_entries(kSample, "flows-admin", "stg", {{"X", "X"}});
    assert(out.find("  stg:\n    secrets:\n      X:\n        env_var_name: X\n") != std::string::npos);
    assert(parse_manifest(out, "t").envs.at("stg")[0].path == "stg/flows-admin/X");
}

void test_insert_rejects_inline_and_mismatch() {
    assert(throws_with([] { manifest_with_entries(kSample, "flows-admin", "prod", {{"X", "X"}}); },
                       "inline value"));
    assert(throws_with([] { manifest_with_entries(kSample, "other", "dev", {{"X", "X"}}); },
                       "names project"));
    // An existing entry that would make exec read another key or set another var.
    assert(throws_with([] { manifest_with_entries(kSample, "flows-admin", "dev", {{"database-url", "OTHER"}}); },
                       "different key or env_var_name"));
    assert(throws_with(
        [] { manifest_with_entries(kSample, "flows-admin", "dev", {{"openai-key", "OPENAI_API_KEY"}}); },
        "different key or env_var_name"));
    assert(manifest_with_entries(kSample, "flows-admin", "dev", {{"database-url", "DATABASE_URL"}}) == kSample);
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
    // Trailing blank lines stay at the end, below the appended env block.
    assert(manifest_with_entries("name: p\n\n\n", "p", "dev", {{"A", "A"}}) ==
           "name: p\nenv:\n  dev:\n    secrets:\n      A:\n        env_var_name: A\n\n\n");
    // split_lines keeps a missing final newline and interior blank lines.
    assert(manifest_with_entries("name: p\n\n# tail", "p", "dev", {{"A", "A"}}) ==
           "name: p\n\n# tail\nenv:\n  dev:\n    secrets:\n      A:\n        env_var_name: A\n");
}

void write_private(const std::string& path, const std::string& text) {
    { std::ofstream f(path); f << text; }
    assert(::chmod(path.c_str(), 0600) == 0);
}

void test_registry() {
    std::string path = g_dir + "/projects.yaml";
    write_private(path, "projects:\n  demo:\n    root: \"${HOME}\"\n  broken:\n    root: /nonexistent/xyz\n  flat: x\n");
    std::optional<std::string> root = registry_project_root(path, "demo");
    assert(root && *root == std::getenv("HOME"));
    assert(!registry_project_root(path, "nope"));
    assert(!registry_project_root(g_dir + "/missing.yaml", "demo"));
    assert(throws_with([&] { registry_project_root(path, "broken"); }, "project root not found"));
    assert(throws_with([&] { registry_project_root(path, "flat"); }, "project 'flat' has no 'root'"));
    std::string listed = g_dir + "/listed.yaml";
    write_private(listed, "projects: [demo]\n");
    assert(throws_with([&] { registry_project_root(listed, "demo"); }, "'projects' must be a mapping"));
    std::string scalar = g_dir + "/scalar.yaml";
    write_private(scalar, "just text\n");
    assert(throws_with([&] { registry_project_root(scalar, "demo"); }, ("registry '" + scalar + "': ").c_str()));
}

void test_registry_write_targets_and_trust() {
    std::string path = g_dir + "/targets.yaml";
    assert(registry_write_targets(g_dir + "/absent.yaml").empty());
    write_private(path, "projects: {}\n");
    assert(registry_write_targets(path).empty());
    write_private(path, "write_targets:\n  - aws-account:123456789012\n  - gcp:acme-secrets\nprojects: {}\n");
    assert((registry_write_targets(path) == std::vector<std::string>{"aws-account:123456789012", "gcp:acme-secrets"}));
    for (const char* bad : {"aws-account:12345", "aws-account:12345678901x", "gcp:Acme", "gcp:123456789012", "gcp:", "aws:us-east-1",
                            "arn:aws:secretsmanager:us-east-1:123456789012:secret:x", "[a]"}) {
        write_private(path, std::string("write_targets: [\"") + bad + "\"]\n");
        assert(throws_with([&] { registry_write_targets(path); }, "write_targets entry"));
    }
    write_private(path, "write_targets: gcp:acme-secrets\n");
    assert(throws_with([&] { registry_write_targets(path); }, "'write_targets' must be a list"));

    // Compat break 3: the registry goes through the manifests' owner/mode check.
    write_private(path, "write_targets: [gcp:acme-secrets]\nprojects: {demo: {root: /tmp}}\n");
    assert(::chmod(path.c_str(), 0646) == 0);
    assert(throws_with([&] { registry_write_targets(path); }, ("writable by everyone; fix with: chmod o-w '" + path + "'").c_str()));
    assert(throws_with([&] { registry_project_root(path, "demo"); }, "writable by everyone"));
    assert(::chmod(path.c_str(), 0600) == 0);
    assert(registry_project_root(path, "demo"));

    std::string open_dir = g_dir + "/open_config";
    assert(::mkdir(open_dir.c_str(), 0700) == 0);
    write_private(open_dir + "/projects.yaml", "write_targets: [gcp:acme-secrets]\n");
    assert(::chmod(open_dir.c_str(), 0757) == 0);
    assert(throws_with([&] { registry_write_targets(open_dir + "/projects.yaml"); }, ("manifest directory '" + open_dir + "'").c_str()));
    assert(::chmod(open_dir.c_str(), 0700) == 0);
}

const std::string kAwsHeader = "name: p\nbackend:\n  type: aws\n  region: us-east-1\n";
const std::string kGcpHeader = "name: p\nbackend:\n  type: gcp\n  project: acme-secrets\n";

std::string entry_yaml(const std::string& body) { return "env:\n  dev:\n    secrets:\n      s:\n        env_var_name: S\n" + body; }

void test_backend_block() {
    Manifest local = parse_manifest("name: p\nbackend:\n  type: local\nenv:\n  dev:\n    secrets:\n      s: {env_var_name: S}\n", "t");
    assert(local.backend.type == BackendType::Local && local.envs.at("dev")[0].path == "dev/p/s");
    assert(parse_manifest("name: p\n", "t").backend.type == BackendType::Local);

    Manifest aws = parse_manifest(kAwsHeader + entry_yaml("        path: dev/p/db\n"), "t");
    assert(aws.backend.type == BackendType::Aws && aws.backend.location == "us-east-1");
    const SecretEntry& aws_text = aws.envs.at("dev")[0];
    assert(aws_text.kind == EntryKind::Text && aws_text.path == "dev/p/db" && aws_text.location == "us-east-1" && aws_text.field.empty());

    Manifest gcp = parse_manifest(kGcpHeader + entry_yaml("        path: dev-db\n"), "t");
    assert(gcp.backend.type == BackendType::Gcp && gcp.backend.location == "acme-secrets");
    assert(gcp.envs.at("dev")[0].path == "dev-db" && gcp.envs.at("dev")[0].location == "acme-secrets");

    assert(throws_with([] { parse_manifest("name: p\nbackend: aws\n", "t"); }, "'backend' must be a mapping"));
    assert(throws_with([] { parse_manifest("name: p\nbackend: {}\n", "t"); }, "backend needs a type"));
    assert(throws_with([] { parse_manifest("name: p\nbackend: {type: azure}\n", "t"); }, "backend type 'azure' is not one of local, aws, gcp"));
    assert(throws_with([] { parse_manifest("name: p\nbackend: {type: aws}\n", "t"); }, "backend type aws needs region"));
    assert(throws_with([] { parse_manifest("name: p\nbackend: {type: gcp}\n", "t"); }, "backend type gcp needs project"));
    assert(throws_with([] { parse_manifest("name: p\nbackend: {type: aws, region: us-east-1, project: acme-secrets}\n", "t"); },
                       "backend 'project' is not valid with backend type aws"));
    assert(throws_with([] { parse_manifest("name: p\nbackend: {type: gcp, project: acme-secrets, region: us-east-1}\n", "t"); },
                       "backend 'region' is not valid with backend type gcp"));
    assert(throws_with([] { parse_manifest("name: p\nbackend: {type: local, region: us-east-1}\n", "t"); },
                       "backend 'region' is not valid with backend type local"));
    assert(throws_with([] { parse_manifest("name: p\nbackend: {type: local, project: acme-secrets}\n", "t"); },
                       "backend 'project' is not valid with backend type local"));
    assert(throws_with([] { parse_manifest("name: p\nbackend: {type: aws, region: us-east-1, endpoint: http://x}\n", "t"); },
                       "unknown key 'endpoint' in backend:"));
    assert(throws_with([] { parse_manifest("name: p\nbackend: {type: aws, region: [us-east-1]}\n", "t"); }, "region must be a string"));
}

void test_locations() {
    // AWS region table: unlisted and malformed regions are refused, in backend:, env and ARNs.
    for (const char* region : {"us-east-9", "cn-north-1", "us-gov-west-1", "US-EAST-1", "us-east-1.evil.com/x", ""}) {
        std::string header = std::string("name: p\nbackend: {type: aws, region: \"") + region + "\"}\n";
        assert(throws_with([&] { parse_manifest(header, "t"); }, "is not in this build's region table; upgrade secretov"));
    }
    for (const char* region : {"us-east-1", "eu-west-1", "ap-southeast-2", "sa-east-1", "il-central-1"}) {
        assert(parse_manifest(std::string("name: p\nbackend: {type: aws, region: ") + region + "}\n", "t").backend.location == region);
    }

    // Per-env location overrides the backend's for name paths.
    Manifest aws = parse_manifest(kAwsHeader + "env:\n  prod:\n    region: eu-west-1\n    secrets:\n      s:\n        env_var_name: S\n        path: prod/p/db\n"
                                               "  dev:\n    secrets:\n      s:\n        env_var_name: S\n        path: dev/p/db\n", "t");
    assert(aws.envs.at("prod")[0].location == "eu-west-1" && aws.envs.at("dev")[0].location == "us-east-1");
    assert(throws_with([] { parse_manifest(kAwsHeader + "env:\n  prod:\n    region: us-east-9\n", "t"); }, "env 'prod' region 'us-east-9' is not in this build's region table"));
    assert(throws_with([] { parse_manifest(kAwsHeader + "env:\n  prod:\n    project: acme-secrets\n", "t"); },
                       "env 'prod' 'project' is not valid with backend type aws"));
    assert(throws_with([] { parse_manifest("name: p\nenv:\n  prod:\n    region: us-east-1\n", "t"); },
                       "env 'prod' 'region' is not valid with backend type local"));
    assert(throws_with([] { parse_manifest("name: p\nenv:\n  prod:\n    project: acme-secrets\n", "t"); },
                       "env 'prod' 'project' is not valid with backend type local"));
    assert(throws_with([] { parse_manifest(kGcpHeader + "env:\n  prod:\n    region: us-east-1\n", "t"); },
                       "env 'prod' 'region' is not valid with backend type gcp"));

    Manifest gcp = parse_manifest(kGcpHeader + "env:\n  prod:\n    project: acme-prod\n    secrets:\n      s:\n        env_var_name: S\n        path: db\n", "t");
    assert(gcp.envs.at("prod")[0].location == "acme-prod");
    assert(throws_with([] { parse_manifest(kGcpHeader + "env:\n  prod:\n    project: Acme-Prod\n", "t"); }, "is not a valid GCP project id"));

    // GCP project ids: lowercase id form only.
    for (const char* project : {"Acme-secrets", "123456789012", "acme", "acme-secrets-", "-acme-secrets", "example.com:proj", "acme_secrets",
                                "a234567890123456789012345678901"}) {
        std::string header = std::string("name: p\nbackend: {type: gcp, project: \"") + project + "\"}\n";
        assert(throws_with([&] { parse_manifest(header, "t"); }, "is not a valid GCP project id"));
    }
    assert(parse_manifest("name: p\nbackend: {type: gcp, project: a23456789012345678901234567890}\n", "t").backend.type == BackendType::Gcp);
}

void test_cloud_paths() {
    auto aws_path = [](const std::string& path) {
        return parse_manifest(kAwsHeader + entry_yaml("        path: \"" + path + "\"\n"), "t").envs.at("dev")[0];
    };
    assert(aws_path("a/B_c+d=e.f@g-h").location == "us-east-1");
    assert(aws_path(std::string(512, 'a')).path.size() == 512);
    for (const std::string& bad : {std::string(513, 'a'), std::string("has space"), std::string("semi;colon"), std::string("q?x"), std::string("a%2Fb"),
                                   std::string("a#b"), std::string("")}) {
        assert(throws_with([&] { aws_path(bad); }, bad.empty() ? "has an empty path" : "is not a valid AWS secret name or ARN"));
    }
    const std::string kArn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:shared/stripe-AbCdEf";
    assert(aws_path(kArn).location == "eu-west-1" && aws_path(kArn).path == kArn);
    for (const char* bad : {"arn:aws-cn:secretsmanager:cn-north-1:123456789012:secret:x", "arn:aws-us-gov:secretsmanager:us-gov-west-1:123456789012:secret:x",
                            "arn:aws:s3:eu-west-1:123456789012:secret:x", "arn:aws:secretsmanager:eu-west-1:12345678901:secret:x",
                            "arn:aws:secretsmanager:eu-west-1:123456789012:parameter:x", "arn:aws:secretsmanager:eu-west-1:123456789012:secret:",
                            "arn:aws:secretsmanager:eu-west-1:123456789012:secret:x:y", "arn:aws:secretsmanager:eu-west-1:123456789012:secret:a b",
                            "arn:aws:secretsmanager:eu-west-1"}) {
        assert(throws_with([&] { aws_path(bad); }, "is not a valid ARN"));
    }
    assert(throws_with([&] { aws_path("arn:aws:secretsmanager:eu-west-9:123456789012:secret:x"); }, "ARN region 'eu-west-9' is not in this build's region table"));

    auto gcp_path = [](const std::string& path) {
        return parse_manifest(kGcpHeader + entry_yaml("        path: \"" + path + "\"\n"), "t").envs.at("dev")[0];
    };
    assert(gcp_path("dev-db_1").location == "acme-secrets");
    assert(gcp_path(std::string(255, 'a')).path.size() == 255);
    assert(gcp_path("projects/acme-shared/secrets/stripe-key").location == "acme-shared");
    for (const std::string& bad : {std::string(256, 'a'), std::string("has space"), std::string("a/b"), std::string("a.b"), std::string("a?b"), std::string("a%2Fb")}) {
        assert(throws_with([&] { gcp_path(bad); }, "is not a valid GCP secret id or resource name"));
    }
    for (const char* bad : {"projects/acme-shared", "projects/acme-shared/secrets", "projects/acme-shared/secrets/", "projects/acme-shared/secrets/a/versions/1",
                            "projects/Acme/secrets/x", "projects/123456789012/secrets/x", "projects/example.com:proj/secrets/x",
                            "projects/acme-shared/topics/x", "projects/acme-shared/secrets/a b"}) {
        assert(throws_with([&] { gcp_path(bad); }, "is not a valid resource name"));
    }
}

void test_kinds() {
    Manifest aws = parse_manifest(kAwsHeader +
                                      "env:\n  dev:\n    secrets:\n"
                                      "      user: {env_var_name: DB_USER, kind: kv, path: dev/p/db, key: username}\n"
                                      "      pass: {env_var_name: DB_PASSWORD, kind: kv, path: dev/p/db, key: password}\n"
                                      "      url: {env_var_name: URL, kind: text, path: dev/p/url}\n",
                                  "t");
    const auto& entries = aws.envs.at("dev");
    assert(entries[0].kind == EntryKind::Kv && entries[0].path == "dev/p/db" && entries[0].field == "username");
    assert(entries[1].field == "password" && entries[2].kind == EntryKind::Text && entries[2].field.empty());

    // kv is a parse error on local, and so is path:.
    assert(throws_with([] { parse_manifest("name: p\n" + entry_yaml("        kind: kv\n        key: k\n"), "t"); }, "kind kv needs a cloud backend"));
    assert(throws_with([] { parse_manifest("name: p\n" + entry_yaml("        kind: kv\n"), "t"); }, "kind kv needs a cloud backend"));
    assert(throws_with([] { parse_manifest("name: p\n" + entry_yaml("        path: x\n"), "t"); }, "path is for cloud backends"));
    assert(parse_manifest("name: p\n" + entry_yaml("        kind: text\n        key: shared/k\n"), "t").envs.at("dev")[0].path == "shared/k");
    assert(throws_with([] { parse_manifest("name: p\n" + entry_yaml("        kind: json\n"), "t"); }, "kind must be text or kv"));
    assert(throws_with([] { parse_manifest("name: p\n" + entry_yaml("        kind: [kv]\n"), "t"); }, "kind must be a string"));

    for (const std::string& header : {kAwsHeader, kGcpHeader}) {
        // Cloud entries never derive a path.
        assert(throws_with([&] { parse_manifest(header + entry_yaml(""), "t"); }, "needs an explicit path"));
        assert(throws_with([&] { parse_manifest(header + entry_yaml("        key: k\n"), "t"); }, "needs an explicit path"));
        assert(throws_with([&] { parse_manifest(header + entry_yaml("        kind: kv\n        key: k\n"), "t"); }, "needs an explicit path"));
        assert(throws_with([&] { parse_manifest(header + entry_yaml("        kind: kv\n        path: x\n"), "t"); }, "kind kv needs key"));
        assert(throws_with([&] { parse_manifest(header + entry_yaml("        path: x\n        key: k\n"), "t"); }, "needs kind: kv"));
        assert(throws_with([&] { parse_manifest(header + entry_yaml("        kind: text\n        path: x\n        key: k\n"), "t"); }, "needs kind: kv"));
        assert(throws_with([&] { parse_manifest(header + entry_yaml("        kind: kv\n        path: x\n        key: \"\"\n"), "t"); }, "has an empty key"));
        assert(throws_with([&] { parse_manifest(header + entry_yaml("        path: [x]\n"), "t"); }, "path must be a string"));
    }
}

// Compat break 1: keys no parser reads are refused at every level.
void test_unknown_keys() {
    assert(throws_with([] { parse_manifest("name: p\nsecrests: {}\n", "t"); }, "unknown key 'secrests' in .secretov.yaml"));
    assert(throws_with([] { parse_manifest("name: p\nenv:\n  dev:\n    secrests: {}\n", "t"); }, "unknown key 'secrests' in env 'dev'"));
    assert(throws_with([] { parse_manifest("name: p\nenv:\n  dev:\n    secrets:\n      s: {env_var_name: S, keyy: k}\n", "t"); },
                       "unknown key 'keyy' in secret 's' (env dev)"));
    assert(throws_with([&] { parse_manifest(kAwsHeader + "endpoint: http://x\n", "t"); }, "unknown key 'endpoint' in .secretov.yaml"));
    assert(throws_with([&] { parse_manifest(kAwsHeader + "env:\n  dev:\n    endpoint: x\n", "t"); }, "unknown key 'endpoint' in env 'dev'"));
    assert(throws_with([&] { parse_manifest(kAwsHeader + entry_yaml("        path: x\n        endpoint: x\n"), "t"); }, "unknown key 'endpoint' in secret 's'"));
    // Every documented key still loads.
    parse_manifest("version: \"1\"\nname: p\ndefault_env: dev\nbackend: {type: local}\nenv:\n  dev:\n    vars: {A: b}\n    secrets: {}\n", "t");
}

// Compat break 2: newly denied names.
void test_cloud_denied_env_names() {
    for (const char* name : {"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3", "aws_endpoint_url_secrets_manager", "CLOUDSDK_CONFIG", "CLOUDSDK_CORE_PROJECT",
                             "cloudsdk_api_endpoint_overrides_secretmanager", "AWS_EC2_METADATA_SERVICE_ENDPOINT", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                             "AWS_WEB_IDENTITY_TOKEN_FILE", "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_UNIVERSE_DOMAIN", "GCE_METADATA_HOST",
                             "GCE_METADATA_IP", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "aws_profile"}) {
        std::string as_var = std::string("name: p\nenv:\n  dev:\n    vars:\n      ") + name + ": x\n";
        assert(throws_with([&] { parse_manifest(as_var, "t"); }, "cannot be set from a manifest"));
        std::string as_secret = std::string("name: p\nenv:\n  dev:\n    secrets:\n      s:\n        env_var_name: ") + name + "\n";
        assert(throws_with([&] { parse_manifest(as_secret, "t"); }, "cannot be set from a manifest"));
    }
    // The design leaves these allowed: ignored by secretov, or holding a secret rather than a loader path.
    Manifest allowed = parse_manifest(
        "name: p\nenv:\n  dev:\n    vars:\n      AWS_REGION: a\n      AWS_DEFAULT_REGION: b\n      GOOGLE_CLOUD_QUOTA_PROJECT: c\n"
        "      AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: d\n      AWS_ACCESS_KEY_ID: e\n      AWS_SECRET_ACCESS_KEY: f\n      AWS_SESSION_TOKEN: g\n"
        "      AWS_ENDPOINT: h\n      GOOGLE_API_KEY: i\n",
        "t");
    assert(allowed.vars.at("dev").size() == 9);
}

void test_insert_into_local_backend_manifest() {
    const std::string text =
        "name: p\n"
        "backend:\n"
        "  type: local\n"
        "env:\n"
        "  dev:\n"
        "    secrets:\n"
        "      a:\n"
        "        kind: text\n"
        "        key: shared/a\n"
        "        env_var_name: A\n";
    std::string out = manifest_with_entries(text, "p", "dev", {{"B", "B"}});
    assert(out == text + "      B:\n        env_var_name: B\n");
    Manifest m = parse_manifest(out, "t");
    assert(m.envs.at("dev").size() == 2 && m.envs.at("dev")[0].path == "shared/a" && m.envs.at("dev")[1].path == "dev/p/B");
}

void test_find_manifest_upward() {
    std::string nested = g_dir + "/a/b";
    assert(::mkdir((g_dir + "/a").c_str(), 0700) == 0);
    assert(::mkdir(nested.c_str(), 0700) == 0);
    assert(!find_manifest_upward(nested));
    { std::ofstream f(g_dir + "/a/.secretov.yaml"); f << "name: a\n"; }
    std::optional<std::string> found = find_manifest_upward(nested);
    assert(found && *found == g_dir + "/a/.secretov.yaml");
    // "/" belongs to root, so the walk never looks at /.secretov.yaml.
    assert(!find_manifest_upward("/"));
}

void write_manifest(const std::string& path, mode_t mode) {
    { std::ofstream f(path); f << "name: t\n"; }
    assert(::chmod(path.c_str(), mode) == 0);
}

// Expectations here are written out by hand, not derived from the code under
// test, so a membership bug cannot hide behind its own oracle.
void test_collect_group_members() {
    const gid_t kPrivate = 1000;
    const uid_t kMe = 1000;
    const std::string kMeName = "roudy";

    GroupMembers alone = collect_group_members(kPrivate, kMe, kMeName, {{"roudy", 1000, {}}, {"docker", 999, {"bob"}}},
                                               {{"roudy", 1000, 1000}, {"bob", 1001, 1001}});
    assert(alone.group == "roudy" && ours_alone(alone));

    // We are skipped even when listed in our own group or met twice.
    GroupMembers self_listed = collect_group_members(kPrivate, kMe, kMeName, {{"roudy", 1000, {"roudy"}}, {"roudy", 1000, {"roudy"}}},
                                                     {{"roudy", 1000, 1000}});
    assert(ours_alone(self_listed) && self_listed.other_names.empty());

    // Another account whose primary group it is.
    GroupMembers primary = collect_group_members(kPrivate, kMe, kMeName, {{"roudy", 1000, {}}},
                                                 {{"roudy", 1000, 1000}, {"devuser", 1001, 1000}, {"devuser", 1001, 1000}});
    assert(!ours_alone(primary) && primary.primary == std::vector<std::string>{"devuser"});

    // A member listed only in getgrgid's entry (a backend that does not
    // enumerate) still counts, once.
    GroupMembers first_entry_only = collect_group_members(kPrivate, kMe, kMeName, {{"roudy", 1000, {"alice"}}}, {});
    assert(!ours_alone(first_entry_only) && first_entry_only.supplementary.size() == 1 &&
           first_entry_only.supplementary[0].user == "alice" && first_entry_only.supplementary[0].group == "roudy");
    GroupMembers counted_once = collect_group_members(kPrivate, kMe, kMeName, {{"roudy", 1000, {"alice"}}, {"roudy", 1000, {"alice"}}}, {});
    assert(counted_once.supplementary.size() == 1);

    // A second name on the gid refuses with or without members.
    GroupMembers alias_empty = collect_group_members(kPrivate, kMe, kMeName, {{"roudy", 1000, {}}, {"roudy", 1000, {}}, {"share", 1000, {}}}, {});
    assert(!ours_alone(alias_empty) && alias_empty.other_names == std::vector<std::string>{"share"} &&
           alias_empty.supplementary.empty());
    GroupMembers alias_members = collect_group_members(kPrivate, kMe, kMeName, {{"roudy", 1000, {}}, {"share", 1000, {"alice", "roudy"}}}, {});
    assert(alias_members.supplementary.size() == 1 && alias_members.supplementary[0].user == "alice" &&
           alias_members.supplementary[0].group == "share");

    // The first entry names the group, so a foreign name is visible to the
    // caller's private-group check.
    GroupMembers foreign = collect_group_members(kPrivate, kMe, kMeName, {{"staff", 1000, {}}}, {});
    assert(foreign.group == "staff");
}

void test_manifest_trust() {
    std::string dir = g_dir + "/trust";
    assert(::mkdir(dir.c_str(), 0700) == 0);
    std::string manifest = dir + "/.secretov.yaml";
    write_manifest(manifest, 0644);
    assert(load_manifest(manifest).project == "t");

    // Group write passes only when the owning group is our private group with
    // nobody else in it, so the outcome depends on this host's group database.
    assert(::chmod(manifest.c_str(), 0664) == 0);
    struct stat manifest_st{};
    assert(::stat(manifest.c_str(), &manifest_st) == 0);
    std::optional<GroupMembers> members = other_group_members(manifest_st.st_gid);
    const struct passwd* my_entry = ::getpwuid(::getuid());
    bool private_group = my_entry && my_entry->pw_gid == manifest_st.st_gid && members &&
                         members->group == my_entry->pw_name;
    bool private_and_alone = private_group && members->primary.empty() && members->supplementary.empty() &&
                             members->other_names.empty();
    if (private_and_alone) {
        assert(load_manifest(manifest).project == "t");
    } else {
        assert(throws_with([&] { load_manifest(manifest); }, ("fix with: chmod g-w '" + manifest + "'").c_str()));
        if (members && !members->primary.empty()) {
            assert(throws_with([&] { load_manifest(manifest); }, (members->primary[0] + " (its primary group)").c_str()));
        }
        if (members && !members->supplementary.empty()) {
            const ListedMember& listed = members->supplementary[0];
            assert(throws_with([&] { load_manifest(manifest); },
                               ("sudo gpasswd -d " + listed.user + " " + listed.group).c_str()));
        }
    }
    assert(::chmod(manifest.c_str(), 0644) == 0);

    // Group write by any group but our private one is refused, file or dir.
    std::vector<gid_t> my_groups(static_cast<std::size_t>(::getgroups(0, nullptr)));
    my_groups.resize(static_cast<std::size_t>(::getgroups(static_cast<int>(my_groups.size()), my_groups.data())));
    std::optional<gid_t> other_gid;
    for (gid_t candidate : my_groups) {
        if (!my_entry || candidate != my_entry->pw_gid) other_gid = candidate;
    }
    if (other_gid) {
        assert(::chown(manifest.c_str(), static_cast<uid_t>(-1), *other_gid) == 0);
        assert(::chmod(manifest.c_str(), 0664) == 0);
        assert(throws_with([&] { load_manifest(manifest); }, "which is not your private group"));
        assert(::chmod(manifest.c_str(), 0644) == 0);
        assert(::chown(manifest.c_str(), static_cast<uid_t>(-1), manifest_st.st_gid) == 0);

        struct stat dir_st{};
        assert(::stat(dir.c_str(), &dir_st) == 0);
        assert(::chown(dir.c_str(), static_cast<uid_t>(-1), *other_gid) == 0);
        assert(::chmod(dir.c_str(), 0770) == 0);
        assert(throws_with([&] { load_manifest(manifest); }, ("manifest directory '" + dir + "'").c_str()));
        assert(throws_with([&] { load_manifest(manifest); }, "which is not your private group"));
        assert(::chmod(dir.c_str(), 0700) == 0);
        assert(::chown(dir.c_str(), static_cast<uid_t>(-1), dir_st.st_gid) == 0);
    } else {
        std::fprintf(stderr, "skip: no supplementary group to test non-private group write\n");
    }

    // An ACL entry for another account sets the group bits as its mask, so a
    // private-group file that would otherwise pass is refused. Needs setfacl.
    if (private_and_alone && std::system(("setfacl -m u:65534:rw '" + manifest + "' 2>/dev/null").c_str()) == 0) {
        assert(throws_with([&] { load_manifest(manifest); }, ("setfacl -b '" + manifest + "'").c_str()));
        assert(std::system(("setfacl -b '" + manifest + "'").c_str()) == 0);
        assert(::chmod(manifest.c_str(), 0664) == 0);
        assert(load_manifest(manifest).project == "t");
        assert(::chmod(manifest.c_str(), 0644) == 0);

        assert(std::system(("setfacl -m u:65534:rwx '" + dir + "'").c_str()) == 0);
        assert(throws_with([&] { load_manifest(manifest); }, ("manifest directory '" + dir + "': has an ACL").c_str()));
        assert(std::system(("setfacl -b '" + dir + "'").c_str()) == 0);
        assert(::chmod(dir.c_str(), 0700) == 0);
    } else {
        std::fprintf(stderr, "skip: ACL test needs a private group, setfacl, and ACL support in /tmp\n");
    }

    assert(::chmod(manifest.c_str(), 0646) == 0);
    assert(throws_with([&] { load_manifest(manifest); }, ("writable by everyone; fix with: chmod o-w '" + manifest + "'").c_str()));
    assert(::chmod(manifest.c_str(), 0644) == 0);

    assert(::chmod(dir.c_str(), 0757) == 0);
    assert(throws_with([&] { load_manifest(manifest); }, ("manifest directory '" + dir + "'").c_str()));
    assert(::chmod(dir.c_str(), 0700) == 0);

    // A bad manifest nearer cwd is reported, never skipped for a good ancestor.
    std::string child = dir + "/child";
    assert(::mkdir(child.c_str(), 0700) == 0);
    write_manifest(child + "/.secretov.yaml", 0666);
    std::optional<std::string> found = find_manifest_upward(child);
    assert(found && *found == child + "/.secretov.yaml");
    assert(throws_with([&] { load_manifest(*found); }, "writable by everyone"));

    // A symlink is judged by its target's directory too.
    std::string open_dir = g_dir + "/open";
    assert(::mkdir(open_dir.c_str(), 0700) == 0 && ::chmod(open_dir.c_str(), 0777) == 0);
    write_manifest(open_dir + "/m.yaml", 0644);
    std::string linked = dir + "/linked";
    assert(::mkdir(linked.c_str(), 0700) == 0);
    assert(::symlink((open_dir + "/m.yaml").c_str(), (linked + "/.secretov.yaml").c_str()) == 0);
    assert(throws_with([&] { load_manifest(linked + "/.secretov.yaml"); }, open_dir.c_str()));
}

void test_denied_env_names() {
    for (const char* name : {"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "BASH_ENV", "NODE_OPTIONS", "SECRETOV_ENV",
                             "PAGER", "GIT_CONFIG_COUNT", "XDG_RUNTIME_DIR", "PATH", "HOME", "PSQLRC",
                             "https_proxy", "Https_Proxy", "FTP_PROXY", "OPENSSL_CONF", "GOFLAGS",
                             "npm_config_script_shell", "LUA_INIT", "Ld_Preload", "SSLKEYLOGFILE",
                             "PYTHONWARNINGS", "BROWSER", "GLIBC_TUNABLES", "GOPROXY", "PIP_INDEX_URL",
                             "UV_INDEX_URL", "CARGO_BUILD_RUSTC_WRAPPER", "RUSTC_WRAPPER", "DOTNET_STARTUP_HOOKS",
                             "NODE_TLS_REJECT_UNAUTHORIZED", "AWS_CA_BUNDLE", "SHELLOPTS", "CC", "cxx", "GOWORK",
                             "MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS", "CARGO_REGISTRIES_X_INDEX", "UV_PUBLISH_URL",
                             "CARGO_REGISTRIES__TOKEN"}) {
        std::string as_var = std::string("name: p\nenv:\n  dev:\n    vars:\n      ") + name + ": x\n";
        assert(throws_with([&] { parse_manifest(as_var, "t"); }, "cannot be set from a manifest"));
        std::string as_secret =
            std::string("name: p\nenv:\n  dev:\n    secrets:\n      s:\n        env_var_name: ") + name + "\n";
        assert(throws_with([&] { parse_manifest(as_secret, "t"); }, "cannot be set from a manifest"));
    }
    // Look-alikes pass: deny entries are exact names or prefixes.
    Manifest m = parse_manifest("name: p\nenv:\n  dev:\n    vars:\n      PATHS: /x\n      ENVIRONMENT: y\n      no_proxy: z\n      PROXY: w\n      GOOGLE_API_KEY: k\n", "t");
    assert(m.vars.at("dev").size() == 5);
    // Registry credentials under a denied prefix are secrets, not loader paths.
    Manifest creds = parse_manifest(
        "name: p\nenv:\n  dev:\n    secrets:\n"
        "      a: {env_var_name: CARGO_REGISTRY_TOKEN}\n      b: {env_var_name: CARGO_REGISTRIES_MY_CO_TOKEN}\n"
        "      c: {env_var_name: UV_PUBLISH_TOKEN}\n      d: {env_var_name: UV_PUBLISH_PASSWORD}\n"
        "      e: {env_var_name: UV_PUBLISH_USERNAME}\n",
        "t");
    assert(creds.envs.at("dev").size() == 5);
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
    test_registry_write_targets_and_trust();
    test_backend_block();
    test_locations();
    test_cloud_paths();
    test_kinds();
    test_unknown_keys();
    test_insert_into_local_backend_manifest();
    test_find_manifest_upward();
    test_collect_group_members();
    test_manifest_trust();
    test_denied_env_names();
    test_cloud_denied_env_names();

    std::filesystem::remove_all(g_dir);
    std::printf("OK\n");
    return 0;
}
