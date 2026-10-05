# Bazarish project (c) 2026
cmake_minimum_required(VERSION 3.20)
project(bazarish-service-node CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# The common library lives in a sibling repository inside the workspace.
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

add_library(bazarish_service_lib STATIC
    src/SubscriptionStore.cpp
    src/AccountApi.cpp
    src/Messages.cpp
    src/PortalApi.cpp
    src/GrantStore.cpp
    src/NodeSettings.cpp
    src/OperatorPush.cpp
)
target_include_directories(bazarish_service_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(bazarish_service_lib PUBLIC Bazarish::Common Threads::Threads bazarish_server_shared)
target_compile_options(bazarish_service_lib PRIVATE -Wall -Wextra -Werror)
# The HTTPS leg of common's HTTP client (hosted payment gateways) needs the TLS
# library; OpenSSL::Crypto already comes transitively via common.
find_package(OpenSSL 3.5 REQUIRED)
target_link_libraries(bazarish_service_lib PUBLIC OpenSSL::SSL)

add_executable(bazarish-service-node src/Main.cpp)
target_link_libraries(bazarish-service-node PRIVATE bazarish_service_lib)
target_compile_options(bazarish-service-node PRIVATE -Wall -Wextra -Werror)

enable_testing()

function(bazarish_service_add_test name)
    add_executable(${name} tests/${name}.cpp)
    target_link_libraries(${name} PRIVATE bazarish_service_lib)
    target_compile_options(${name} PRIVATE -Wall -Wextra -Werror)
    # The portal's web files, for the tests that render a page.
    target_compile_definitions(${name} PRIVATE
        BAZARISH_PORTAL_ASSETS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/portal")
    add_test(NAME ${name} COMMAND ${name})
endfunction()

bazarish_service_add_test(TestSubscriptionStore)
bazarish_service_add_test(TestAccountApi)
bazarish_service_add_test(TestGrantStore)
bazarish_service_add_test(TestModeratedRegistration)
bazarish_service_add_test(TestPortal)
bazarish_service_add_test(TestOperatorApi)
