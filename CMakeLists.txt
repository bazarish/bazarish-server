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
    # the client core in common stays out of this build.
    set(BAZARISH_WITH_CLIENT OFF CACHE BOOL "Build the client core library" FORCE)
    add_subdirectory(${BAZARISH_COMMON_DIR} bazarish-common)
endif()

find_package(Threads REQUIRED)
find_package(OpenSSL 3.5 REQUIRED)

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

# A live check against a real gateway. Not an add_test: it needs one running,
# the way i2p_smoke needs a network.
# The address parser lives with the client core, which a gateway build leaves
# out; the one file comes along rather than the whole of it.
add_executable(gateway_smoke tests/GatewaySmoke.cpp
    ${BAZARISH_COMMON_DIR}/client/GatewayAddress.cpp)
target_link_libraries(gateway_smoke PRIVATE bazarish_gateway_lib)
target_include_directories(gateway_smoke PRIVATE ${BAZARISH_COMMON_DIR}/client)
target_compile_options(gateway_smoke PRIVATE -Wall -Wextra -Werror)

enable_testing()
function(bazarish_gateway_add_test name)
    add_executable(${name} tests/${name}.cpp)
    target_link_libraries(${name} PRIVATE bazarish_gateway_lib)
    target_include_directories(${name} PRIVATE ${BAZARISH_COMMON_DIR}/tests)
    target_compile_options(${name} PRIVATE -Wall -Wextra -Werror)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

bazarish_gateway_add_test(TestControlChurn)
bazarish_gateway_add_test(TestGateway)
bazarish_gateway_add_test(TestGatewayClient)
bazarish_gateway_add_test(TestLocalMeeting)
bazarish_gateway_add_test(TestMediaLane)
bazarish_gateway_add_test(TestLostCredit)
bazarish_gateway_add_test(TestLostFrame)
bazarish_gateway_add_test(TestLostDest)
bazarish_gateway_add_test(TestSessions)
bazarish_gateway_add_test(TestSettings)
