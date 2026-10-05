# Bazarish project (c) 2026
cmake_minimum_required(VERSION 3.20)
project(bazarish-server-core CXX)

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

# What the servers here share and the client has no use for. Beside this
# component when the whole repository is built, a sibling when it is not.
if(NOT TARGET bazarish_server_shared)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/shared/CMakeLists.txt")
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/shared bazarish-server-shared)
    else()
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../shared bazarish-server-shared)
    endif()
endif()

find_package(Threads REQUIRED)

add_library(bazarish_server_lib STATIC
    src/DiskStorage.cpp
    src/DeliveryEngine.cpp
    src/Federation.cpp
    src/PerUserDestinations.cpp
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
bazarish_server_add_test(TestPerUserDestinations)
bazarish_server_add_test(TestSessionStore)
bazarish_server_add_test(TestTunnelFace)
