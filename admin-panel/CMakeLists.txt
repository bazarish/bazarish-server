# Bazarish project (c) 2026
cmake_minimum_required(VERSION 3.20)
project(bazarish-admin-panel CXX)

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

add_library(bazarish_admin_lib STATIC
    src/Config.cpp
    src/PanelSettings.cpp
    src/AdminAuth.cpp
    src/SessionStore.cpp
    src/ServiceClient.cpp
    src/FleetSync.cpp
    src/HttpApi.cpp
)
target_include_directories(bazarish_admin_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(bazarish_admin_lib PUBLIC Bazarish::Common Threads::Threads bazarish_server_shared)
target_compile_options(bazarish_admin_lib PRIVATE -Wall -Wextra -Werror)

add_executable(bazarish-admin-panel src/Main.cpp)
bazarish_stamp_version(bazarish-admin-panel)
target_link_libraries(bazarish-admin-panel PRIVATE bazarish_admin_lib)
target_compile_options(bazarish-admin-panel PRIVATE -Wall -Wextra -Werror)

enable_testing()

function(bazarish_admin_add_test name)
    add_executable(${name} tests/${name}.cpp)
    target_link_libraries(${name} PRIVATE bazarish_admin_lib)
    target_compile_options(${name} PRIVATE -Wall -Wextra -Werror)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

bazarish_admin_add_test(TestConfig)
bazarish_admin_add_test(TestPanelSettings)
bazarish_admin_add_test(TestAdminAuth)
bazarish_admin_add_test(TestServiceClient)
bazarish_admin_add_test(TestFleetSync)
bazarish_admin_add_test(TestLoginPage)
# The sign-in page is drawn from the shipped web files, so the test renders the
# real template rather than a stand-in that could escape what the real one does not.
target_compile_definitions(TestLoginPage
    PRIVATE BAZARISH_PANEL_WEB_DIR="${CMAKE_CURRENT_SOURCE_DIR}/web")
bazarish_admin_add_test(TestPanelFleet)
target_compile_definitions(TestPanelFleet
    PRIVATE BAZARISH_PANEL_WEB_DIR="${CMAKE_CURRENT_SOURCE_DIR}/web")
