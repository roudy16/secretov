# secretov — all dev workflows go through just

set positional-arguments

# list recipes
default:
    @just --list

# fetch vendored deps if needed, then configure the build (cmake -B build)
setup:
    ./third_party/get-deps.sh
    cmake -B build

# compile
build:
    cmake --build build -j

# run tests (ctest)
test:
    ctest --test-dir build --output-on-failure

# run the binary, passing args through (e.g. `just run daemon`, `just run tui`)
run *args:
    ./build/secretov "$@"

# install (cmake --install)
install:
    cmake --install build

# remove the build directory
clean:
    rm -rf build
