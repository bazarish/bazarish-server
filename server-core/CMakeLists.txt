# Bazarish project (c) 2026
cmake_minimum_required(VERSION 3.20)
project(bazarish-server-core CXX)

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

# What the servers here share and the client has no use for.
if(NOT TARGET bazarish_server_shared)
    add_subdirectory(${BAZARISH_SERVER_ROOT}/shared bazarish-server-shared)
endif()

find_package(Threads REQUIRED)

add_library(bazarish_server_lib STATIC
    src/DiskStorage.cpp
    src/ContactSources.cpp
    src/DeliveryEngine.cpp
    src/Federation.cpp
    src/PerUserDestinations.cpp
    src/GatewayLink.cpp
    src/EventGate.cpp
    src/HttpApi.cpp
    src/ServerSettings.cpp
    src/SessionStore.cpp
)
target_include_directories(bazarish_server_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(bazarish_server_lib PUBLIC Bazarish::Common Threads::Threads bazarish_server_shared)
target_compile_options(bazarish_server_lib PRIVATE -Wall -Wextra -Werror)

add_executable(bazarish-server src/Main.cpp)
target_link_libraries(bazarish-server PRIVATE bazarish_server_lib)
target_compile_options(bazarish-server PRIVATE -Wall -Wextra -Werror)

enable_testing()

function(bazarish_server_add_test name)
    add_executable(${name} tests/${name}.cpp)
    target_link_libraries(${name} PRIVATE bazarish_server_lib)
    target_compile_options(${name} PRIVATE -Wall -Wextra -Werror)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

bazarish_server_add_test(TestDiskStorage)
bazarish_server_add_test(TestEventGate)
bazarish_server_add_test(TestHttpApi)
bazarish_server_add_test(TestFederation)
bazarish_server_add_test(TestGatewayLink)
bazarish_server_add_test(TestPerUserDestinations)
bazarish_server_add_test(TestSessionStore)
bazarish_server_add_test(TestTunnelFace)
