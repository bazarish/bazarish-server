# Bazarish project (c) 2026
# What the servers share and the client has no use for.
add_library(bazarish_server_shared STATIC
    Health.cpp
    LoginRelay.cpp
    OpsClient.cpp
    OpsGate.cpp
    OpsSettings.cpp
    RateLimiter.cpp
    Restart.cpp
    SessionStore.cpp
    StateIdentity.cpp
    TlsPipe.cpp
    TunnelFace.cpp
    WebFace.cpp
)
target_include_directories(bazarish_server_shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bazarish_server_shared PUBLIC bazarish_common)
target_compile_options(bazarish_server_shared PRIVATE -Wall -Wextra -Werror)

# Its own library: only the faces that draw a QR code take libqrencode.
add_library(bazarish_server_qr STATIC QrSvg.cpp SignInScan.cpp)
target_include_directories(bazarish_server_qr PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
find_library(QRENCODE_LIBRARY NAMES qrencode REQUIRED)
find_path(QRENCODE_INCLUDE_DIR NAMES qrencode.h REQUIRED)
target_include_directories(bazarish_server_qr PRIVATE ${QRENCODE_INCLUDE_DIR})
target_link_libraries(bazarish_server_qr PUBLIC bazarish_server_shared PRIVATE ${QRENCODE_LIBRARY})
target_compile_options(bazarish_server_qr PRIVATE -Wall -Wextra -Werror)

# One test of a server library; the source is tests/<name>.cpp of the caller unless named.
function(bazarish_server_test name library)
    set(source tests/${name}.cpp)
    if(ARGC GREATER 2)
        set(source ${ARGV2})
    endif()
    add_executable(${name} ${source})
    target_link_libraries(${name} PRIVATE ${library} bazarish_test_util)
    target_compile_options(${name} PRIVATE -Wall -Wextra -Werror)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

bazarish_server_test(TestRestart bazarish_server_shared TestRestart.cpp)
bazarish_server_test(TestHealth bazarish_server_shared TestHealth.cpp)
bazarish_server_test(TestRateLimiter bazarish_server_shared TestRateLimiter.cpp)
bazarish_server_test(TestTlsPipe bazarish_server_shared TestTlsPipe.cpp)
bazarish_server_test(TestSessionStore bazarish_server_shared TestSessionStore.cpp)
bazarish_server_test(TestQrSvg bazarish_server_qr TestQrSvg.cpp)
