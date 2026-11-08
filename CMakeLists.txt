# Bazarish project (c) 2026
cmake_minimum_required(VERSION 3.20)
project(bazarish CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(BAZARISH_COMMON_DIR "${CMAKE_CURRENT_SOURCE_DIR}/common" CACHE PATH
    "Path to the bazarish common library repository")
set(BAZARISH_WITH_CLIENT OFF CACHE BOOL "Build the client core library" FORCE)
add_subdirectory(${BAZARISH_COMMON_DIR} bazarish-common)

enable_testing()

add_subdirectory(shared)

add_subdirectory(server-core)
add_subdirectory(service-node)
add_subdirectory(facade-http)
add_subdirectory(admin-panel)
add_subdirectory(gateway)
add_subdirectory(setup)
