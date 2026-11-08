# Bazarish project (c) 2026
cmake_minimum_required(VERSION 3.20)
project(bazarish-admin-panel CXX)

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

add_library(bazarish_admin_lib STATIC
    src/Config.cpp
    src/PanelSettings.cpp
    src/AdminAuth.cpp
    src/PanelSessions.cpp
    src/ServiceClient.cpp
    src/FleetSync.cpp
    src/HttpApi.cpp
)
target_include_directories(bazarish_admin_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(bazarish_admin_lib PUBLIC Bazarish::Common Threads::Threads bazarish_server_shared
    bazarish_server_qr)
target_compile_options(bazarish_admin_lib PRIVATE -Wall -Wextra -Werror)

add_executable(bazarish-admin-panel src/Main.cpp)
bazarish_stamp_version(bazarish-admin-panel)
target_link_libraries(bazarish-admin-panel PRIVATE bazarish_admin_lib)
target_compile_options(bazarish-admin-panel PRIVATE -Wall -Wextra -Werror)

enable_testing()

bazarish_server_test(TestConfig bazarish_admin_lib)
bazarish_server_test(TestPanelSettings bazarish_admin_lib)
bazarish_server_test(TestAdminAuth bazarish_admin_lib)
bazarish_server_test(TestServiceClient bazarish_admin_lib)
bazarish_server_test(TestFleetSync bazarish_admin_lib)
bazarish_server_test(TestLoginPage bazarish_admin_lib)
target_compile_definitions(TestLoginPage
    PRIVATE BAZARISH_PANEL_WEB_DIR="${CMAKE_CURRENT_SOURCE_DIR}/web")
bazarish_server_test(TestPanelFleet bazarish_admin_lib)
target_compile_definitions(TestPanelFleet
    PRIVATE BAZARISH_PANEL_WEB_DIR="${CMAKE_CURRENT_SOURCE_DIR}/web")

find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(NAME AdminWebTranslations
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/../tools/check-web-i18n.py
        ${CMAKE_CURRENT_SOURCE_DIR}/web)
