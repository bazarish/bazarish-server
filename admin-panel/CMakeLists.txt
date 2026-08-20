# Bazarish project (c) 2026
cmake_minimum_required(VERSION 3.20)
project(bazarish-admin-panel CXX)

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
    add_subdirectory(${BAZARISH_COMMON_DIR} bazarish-common)
endif()

find_package(Threads REQUIRED)

add_library(bazarish_admin_lib STATIC
    src/Config.cpp
    src/AdminAuth.cpp
    src/SessionStore.cpp
    src/Html.cpp
    src/ServiceClient.cpp
    src/HttpApi.cpp
)
target_include_directories(bazarish_admin_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(bazarish_admin_lib PUBLIC Bazarish::Common Threads::Threads)
target_compile_options(bazarish_admin_lib PRIVATE -Wall -Wextra -Werror)

add_executable(bazarish-admin-panel src/Main.cpp)
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
bazarish_admin_add_test(TestAdminAuth)
bazarish_admin_add_test(TestServiceClient)
