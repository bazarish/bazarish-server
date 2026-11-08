# Bazarish project (c) 2026
cmake_minimum_required(VERSION 3.20)
project(bazarish-service-node CXX)

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
    add_subdirectory(${BAZARISH_COMMON_DIR} bazarish-common)
endif()

if(NOT TARGET bazarish_server_shared)
    add_subdirectory(${BAZARISH_SERVER_ROOT}/shared bazarish-server-shared)
endif()

find_package(Threads REQUIRED)

add_library(bazarish_service_lib STATIC
    src/SubscriptionStore.cpp
    src/AccountApi.cpp
    src/Messages.cpp
    src/PortalApi.cpp
    src/GrantStore.cpp
    src/AccountRemoval.cpp
    src/IdleSweep.cpp
    src/UserLocks.cpp
    src/NodeSettings.cpp
    src/OperatorPush.cpp
    src/LoginMailbox.cpp
)
target_include_directories(bazarish_service_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(bazarish_service_lib PUBLIC Bazarish::Common Threads::Threads bazarish_server_shared
    bazarish_server_qr)
target_compile_options(bazarish_service_lib PRIVATE -Wall -Wextra -Werror)

add_executable(bazarish-service-node src/Main.cpp)
bazarish_stamp_version(bazarish-service-node)
target_link_libraries(bazarish-service-node PRIVATE bazarish_service_lib)
target_compile_options(bazarish-service-node PRIVATE -Wall -Wextra -Werror)

enable_testing()

function(bazarish_service_add_test name)
    bazarish_server_test(${name} bazarish_service_lib)
    target_compile_definitions(${name} PRIVATE
        BAZARISH_PORTAL_ASSETS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/portal")
endfunction()

bazarish_service_add_test(TestSubscriptionStore)
bazarish_service_add_test(TestAccountApi)
bazarish_service_add_test(TestGrantStore)
bazarish_service_add_test(TestIdleSweep)
bazarish_service_add_test(TestModeratedRegistration)
bazarish_service_add_test(TestPortal)
bazarish_service_add_test(TestOperatorApi)
bazarish_service_add_test(TestLoginMailbox)
