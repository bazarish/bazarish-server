# Bazarish project (c) 2026
cmake_minimum_required(VERSION 3.20)
project(bazarish-gateway CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

get_filename_component(BAZARISH_SERVER_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
set(BAZARISH_COMMON_DIR "${BAZARISH_SERVER_ROOT}/common" CACHE PATH
    "Path to the bazarish common library repository")
if(NOT EXISTS "${BAZARISH_COMMON_DIR}/CMakeLists.txt")
    message(FATAL_ERROR "no common library at ${BAZARISH_COMMON_DIR}"
        " - run: git submodule update --init --recursive")
endif()
if(NOT TARGET bazarish_common)
    set(BAZARISH_WITH_CLIENT OFF CACHE BOOL "Build the client core library" FORCE)
    add_subdirectory(${BAZARISH_COMMON_DIR} bazarish-common)
endif()

if(NOT TARGET bazarish_server_shared)
    add_subdirectory(${BAZARISH_SERVER_ROOT}/shared bazarish-server-shared)
endif()

find_package(Threads REQUIRED)
find_package(OpenSSL 3.5 REQUIRED)

add_library(bazarish_gateway_lib STATIC
    src/Conduit.cpp
    src/DestinationPool.cpp
    src/Gateway.cpp
    src/Settings.cpp
    src/Sessions.cpp
)
bazarish_stamp_version(bazarish_gateway_lib)
target_include_directories(bazarish_gateway_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(bazarish_gateway_lib PUBLIC Bazarish::Common Threads::Threads bazarish_server_shared)
target_compile_options(bazarish_gateway_lib PRIVATE -Wall -Wextra -Werror)

add_executable(bazarish-gateway src/Main.cpp)
target_link_libraries(bazarish-gateway PRIVATE bazarish_gateway_lib)
target_compile_options(bazarish-gateway PRIVATE -Wall -Wextra -Werror)


enable_testing()
bazarish_server_test(TestControlChurn bazarish_gateway_lib)
bazarish_server_test(TestDecoyBurst bazarish_gateway_lib)
bazarish_server_test(TestIdleStatus bazarish_gateway_lib)
bazarish_server_test(TestGateway bazarish_gateway_lib)
bazarish_server_test(TestGatewayClient bazarish_gateway_lib)
bazarish_server_test(TestLocalMeeting bazarish_gateway_lib)
bazarish_server_test(TestMediaLane bazarish_gateway_lib)
bazarish_server_test(TestLostCredit bazarish_gateway_lib)
bazarish_server_test(TestLostFrame bazarish_gateway_lib)
bazarish_server_test(TestLostDest bazarish_gateway_lib)
bazarish_server_test(TestSessions bazarish_gateway_lib)
bazarish_server_test(TestSettings bazarish_gateway_lib)
target_compile_definitions(TestSettings
    PRIVATE BAZARISH_GATEWAY_EXAMPLE="${CMAKE_CURRENT_SOURCE_DIR}/config.example.json")
bazarish_server_test(TestOpsSettings bazarish_gateway_lib)
bazarish_server_test(TestDirectRoute bazarish_gateway_lib)
bazarish_server_test(TestStopWhileWriting bazarish_gateway_lib)
bazarish_server_test(TestChurnDirect bazarish_gateway_lib)
bazarish_server_test(TestDropAfterAnswer bazarish_gateway_lib)
bazarish_server_test(TestSilentGateway bazarish_gateway_lib)

if(TARGET bazarish_server_lib)
    bazarish_server_test(TestServerLink bazarish_gateway_lib)
    target_link_libraries(TestServerLink PRIVATE bazarish_server_lib)
endif()
