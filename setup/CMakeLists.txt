# Bazarish project (c) 2026
cmake_minimum_required(VERSION 3.20)
project(bazarish-setup CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# The common library is this repository's own submodule, named and not searched
# for: a directory beside a component must not be able to take its place.
get_filename_component(BAZARISH_SERVER_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
set(BAZARISH_COMMON_DIR "${BAZARISH_SERVER_ROOT}/common" CACHE PATH
    "Path to the bazarish common library repository")
if(NOT EXISTS "${BAZARISH_COMMON_DIR}/CMakeLists.txt")
    message(FATAL_ERROR "no common library at ${BAZARISH_COMMON_DIR}"
        " - run: git submodule update --init --recursive")
endif()
if(NOT TARGET bazarish_common)
    add_subdirectory(${BAZARISH_COMMON_DIR} bazarish-common)
endif()

if(NOT TARGET bazarish_server_shared)
    add_subdirectory(${BAZARISH_SERVER_ROOT}/shared bazarish-server-shared)
endif()

add_library(bazarish_setup_lib STATIC src/FleetSetup.cpp)
target_include_directories(bazarish_setup_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(bazarish_setup_lib PUBLIC Bazarish::Common bazarish_server_shared)
target_compile_options(bazarish_setup_lib PRIVATE -Wall -Wextra -Werror)

add_executable(bazarish-setup src/Main.cpp)
target_link_libraries(bazarish-setup PRIVATE bazarish_setup_lib)
target_compile_options(bazarish-setup PRIVATE -Wall -Wextra -Werror)

enable_testing()

add_executable(TestFleetSetup tests/TestFleetSetup.cpp)
target_link_libraries(TestFleetSetup PRIVATE bazarish_setup_lib)
target_compile_options(TestFleetSetup PRIVATE -Wall -Wextra -Werror)
add_test(NAME TestFleetSetup COMMAND TestFleetSetup)
