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

find_package(Threads REQUIRED)

add_library(bazarish_service_lib STATIC
    src/SubscriptionStore.cpp
    src/AccountApi.cpp
    src/PaymentGateway.cpp
    src/MockPaymentGateway.cpp
    src/MoneroPaymentGateway.cpp
    src/Portal.cpp
    src/LedgerStore.cpp
    src/Hmac.cpp
    src/LoginChallenge.cpp
    src/Captcha.cpp
    src/SelfHostedCaptcha.cpp
    src/PortalSession.cpp
    src/PortalApi.cpp
)
target_include_directories(bazarish_service_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(bazarish_service_lib PUBLIC Bazarish::Common Threads::Threads)
target_compile_options(bazarish_service_lib PRIVATE -Wall -Wextra -Werror)
# Payment backends use httplib's HTTP client with digest auth (monero-wallet-rpc)
# and TLS (future hosted gateways). Define the macro PUBLIC and link OpenSSL::SSL
# so every service-side target that includes httplib agrees (no header-only ODR
# mismatch). OpenSSL::Crypto already comes transitively via common.
find_package(OpenSSL 3.0 REQUIRED)
target_compile_definitions(bazarish_service_lib PUBLIC CPPHTTPLIB_OPENSSL_SUPPORT)
target_link_libraries(bazarish_service_lib PUBLIC OpenSSL::SSL)

add_executable(bazarish-service-node src/Main.cpp)
target_link_libraries(bazarish-service-node PRIVATE bazarish_service_lib)
target_compile_options(bazarish-service-node PRIVATE -Wall -Wextra -Werror)

enable_testing()

function(bazarish_service_add_test name)
    add_executable(${name} tests/${name}.cpp)
    target_link_libraries(${name} PRIVATE bazarish_service_lib)
    target_compile_options(${name} PRIVATE -Wall -Wextra -Werror)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

bazarish_service_add_test(TestSubscriptionStore)
bazarish_service_add_test(TestAccountApi)
bazarish_service_add_test(TestPayments)
bazarish_service_add_test(TestPortal)
bazarish_service_add_test(TestLedger)
bazarish_service_add_test(TestLoginChallenge)
bazarish_service_add_test(TestCaptcha)
bazarish_service_add_test(TestPortalApi)
