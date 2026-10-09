#include "backend.hpp"

// Tests must assert even in Release builds (CMakeLists.txt defaults an unset build type to Release).
#undef NDEBUG
#include <unistd.h>

#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

using namespace secretov;

namespace {

template <typename F>
std::string error_text(F&& call) {
    try {
        call();
    } catch (const std::exception& e) {
        return e.what();
    }
    return "";
}

void test_cloud_backends_are_not_compiled_in() {
    Paths paths;
    for (BackendType type : {BackendType::Aws, BackendType::Gcp}) {
        BackendConfig config;
        config.type = type;
        std::string name = backend_type_name(type);
        std::string option = type == BackendType::Aws ? "AWS" : "GCP";
        assert(error_text([&] { open_backend(config, paths); }) ==
               "backend '" + name + "' not compiled in (rebuild with -DSECRETOV_BACKEND_" + option + "=ON)");
    }
}

// No daemon listens: reads and writes fail as typed errors, a write that never left is not maybe_applied.
void test_local_backend_without_a_daemon() {
    std::filesystem::path dir = std::filesystem::temp_directory_path() / ("secretov_backend_test_" + std::to_string(::getpid()));
    std::filesystem::create_directories(dir);
    Paths paths;
    paths.token = (dir / "token").string();
    paths.socket = (dir / "s.sock").string();

    // A missing token is NoCredentials.
    try {
        open_backend(BackendConfig{}, paths);
        assert(false);
    } catch (const BackendError& e) {
        assert(e.kind == BackendError::Kind::NoCredentials);
    }

    std::ofstream(paths.token) << "deadbeef\n";
    std::unique_ptr<Backend> backend = open_backend(BackendConfig{}, paths);
    try {
        backend->get_many({"dev/p/A", "dev/p/B"});
        assert(false);
    } catch (const BackendError& e) {
        assert(e.kind == BackendError::Kind::Unreachable && e.not_running && !e.maybe_applied && !e.timed_out);
    }
    try {
        backend->set("dev/p/A", "v");
        assert(false);
    } catch (const BackendError& e) {
        assert(e.kind == BackendError::Kind::Unreachable && !e.maybe_applied);
    }
    assert(error_text([&] { backend->restore("dev/p/A"); }) == "this backend cannot restore secrets");
    assert(backend->get_many({}).values.empty());

    std::filesystem::remove_all(dir);
}

}  // namespace

int main() {
    test_cloud_backends_are_not_compiled_in();
    test_local_backend_without_a_daemon();
    return 0;
}
