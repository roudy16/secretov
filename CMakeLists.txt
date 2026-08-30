cmake_minimum_required(VERSION 3.25)  # FetchContent SYSTEM keyword
project(secretov CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)  # clangd; without this only FTXUI's subdir-scoped setting exports
add_compile_options(-Wall -Wextra)

# nlohmann/json: system package first, vendored header fallback.
find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
  add_library(nlohmann_json INTERFACE)
  target_include_directories(nlohmann_json INTERFACE ${CMAKE_SOURCE_DIR}/third_party)
  add_library(nlohmann_json::nlohmann_json ALIAS nlohmann_json)
endif()

# libsodium: pkg-config first, vendored static lib fallback.
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(SODIUM QUIET libsodium)
endif()
if(SODIUM_FOUND)
  add_library(sodium INTERFACE)
  target_include_directories(sodium INTERFACE ${SODIUM_INCLUDE_DIRS})
  target_link_libraries(sodium INTERFACE ${SODIUM_LIBRARIES})
  target_compile_options(sodium INTERFACE ${SODIUM_CFLAGS_OTHER})
else()
  add_library(sodium STATIC IMPORTED)
  set_target_properties(sodium PROPERTIES
    IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/third_party/sodium/lib/libsodium.a
    INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_SOURCE_DIR}/third_party/sodium/include)
endif()

# FTXUI: TUI components. Downloaded at configure time (FetchContent), matching
# this repo's vendored-deps approach. Linked into the secretov binary only, so
# secretov_core and store_test stay free of it. SYSTEM so its headers don't trip
# our -Wall -Wextra.
include(FetchContent)
FetchContent_Declare(ftxui
  GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI.git
  GIT_TAG f921fad208912747c17d129a8ef75ec7624b6eec  # v7.0.3; a hash cannot be moved, a tag can
  SYSTEM)
set(FTXUI_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(FTXUI_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(FTXUI_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(FTXUI_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(ftxui)

# tui.cpp pulls FTXUI; keep it out of secretov_core so store_test never links it.
file(GLOB SECRETOV_CORE_SRC CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/*.cpp)
list(REMOVE_ITEM SECRETOV_CORE_SRC
  ${CMAKE_SOURCE_DIR}/src/main.cpp
  ${CMAKE_SOURCE_DIR}/src/tui.cpp)

add_library(secretov_core STATIC ${SECRETOV_CORE_SRC})
target_include_directories(secretov_core PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(secretov_core PUBLIC sodium nlohmann_json::nlohmann_json)

add_executable(secretov src/main.cpp src/tui.cpp)
target_link_libraries(secretov PRIVATE secretov_core
  ftxui::screen ftxui::dom ftxui::component)
install(TARGETS secretov)

enable_testing()
add_executable(store_test tests/store_test.cpp)
target_link_libraries(store_test PRIVATE secretov_core)
add_test(NAME store_test COMMAND store_test)

add_test(NAME smoke_test
  COMMAND ${CMAKE_SOURCE_DIR}/tests/smoke_test.sh $<TARGET_FILE:secretov>)
