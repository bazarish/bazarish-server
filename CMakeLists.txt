# Bazarish project (c) 2026
cmake_minimum_required(VERSION 3.20)
project(bazarish CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# One build of the common library (and of the embedded i2pd engine) for the whole
# fleet: each component below links these targets instead of compiling its own
# copy. A component still configures standalone from its own directory - there the
# same variable falls back to a sibling checkout of the common repository.
set(BAZARISH_COMMON_DIR "${CMAKE_CURRENT_SOURCE_DIR}/common" CACHE PATH
    "Path to the bazarish common library repository")
# No server here is a client: the client core in common, and the libraries only
# it needs, stay out of this build entirely.
set(BAZARISH_WITH_CLIENT OFF CACHE BOOL "Build the client core library" FORCE)
add_subdirectory(${BAZARISH_COMMON_DIR} bazarish-common)

enable_testing()

add_subdirectory(server-core)
add_subdirectory(service-node)
add_subdirectory(facade-http)
add_subdirectory(admin-panel)
