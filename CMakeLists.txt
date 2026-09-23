# Bazarish project (c) 2026
cmake_minimum_required(VERSION 3.20)
project(bazarish-gateway CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# The common library is a git submodule at ./common; fall back to a sibling
# checkout (../common) for in-workspace multi-repo development.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/common/CMakeLists.txt")
    set(_bazarish_common_default "${CMAKE_CURRENT_SOURCE_DIR}/common")
else()
    set(_bazarish_common_default "${CMAKE_CURRENT_SOURCE_DIR}/../common")
endif()
set(BAZARISH_COMMON_DIR "${_bazarish_common_default}" CACHE PATH
    "Path to the bazarish common library repository")
if(NOT TARGET bazarish_common)
    # A gateway runs a router and serves clients; it is not a client itself, so
    # the client core in common stays out of this build. The embedded engine is
    # the whole point of the daemon and is required.
    set(BAZARISH_WITH_CLIENT OFF CACHE BOOL "Build the client core library" FORCE)
    set(BAZARISH_WITH_I2PD ON CACHE BOOL "Build the embedded libi2pd_bazarish target" FORCE)
    add_subdirectory(${BAZARISH_COMMON_DIR} bazarish-common)
endif()

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

add_library(bazarish_gateway_lib STATIC
    src/Gateway.cpp
    src/Settings.cpp
    src/Sessions.cpp
)
target_include_directories(bazarish_gateway_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(bazarish_gateway_lib PUBLIC Bazarish::Common Threads::Threads)
target_compile_options(bazarish_gateway_lib PRIVATE -Wall -Wextra -Werror)

add_executable(bazarish-gateway src/Main.cpp)
target_link_libraries(bazarish-gateway PRIVATE bazarish_gateway_lib)
target_compile_options(bazarish-gateway PRIVATE -Wall -Wextra -Werror)

enable_testing()
function(bazarish_gateway_add_test name)
    add_executable(${name} tests/${name}.cpp)
    target_link_libraries(${name} PRIVATE bazarish_gateway_lib)
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    target_compile_options(${name} PRIVATE -Wall -Wextra -Werror)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

bazarish_gateway_add_test(TestControlChurn)
bazarish_gateway_add_test(TestGateway)
bazarish_gateway_add_test(TestGatewayClient)
bazarish_gateway_add_test(TestLocalMeeting)
bazarish_gateway_add_test(TestSessions)
