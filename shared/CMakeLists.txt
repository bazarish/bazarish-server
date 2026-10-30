# Bazarish project (c) 2026
# What the servers in this repository share and the client has no use for. The
# common library is the protocol core; this is the four components' own ground.
add_library(bazarish_server_shared STATIC
    Health.cpp
    RateLimiter.cpp
    Restart.cpp
    SessionStore.cpp
    TlsPipe.cpp
    TunnelFace.cpp
)
target_include_directories(bazarish_server_shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bazarish_server_shared PUBLIC bazarish_common)
target_compile_options(bazarish_server_shared PRIVATE -Wall -Wextra -Werror)

add_executable(TestRestart TestRestart.cpp)
target_link_libraries(TestRestart PRIVATE bazarish_server_shared)
target_compile_options(TestRestart PRIVATE -Wall -Wextra -Werror)
add_test(NAME TestRestart COMMAND TestRestart)

add_executable(TestHealth TestHealth.cpp)
target_link_libraries(TestHealth PRIVATE bazarish_server_shared)
target_compile_options(TestHealth PRIVATE -Wall -Wextra -Werror)
add_test(NAME TestHealth COMMAND TestHealth)

add_executable(TestRateLimiter TestRateLimiter.cpp)
target_link_libraries(TestRateLimiter PRIVATE bazarish_server_shared)
target_compile_options(TestRateLimiter PRIVATE -Wall -Wextra -Werror)
add_test(NAME TestRateLimiter COMMAND TestRateLimiter)

add_executable(TestTlsPipe TestTlsPipe.cpp)
target_link_libraries(TestTlsPipe PRIVATE bazarish_server_shared)
target_compile_options(TestTlsPipe PRIVATE -Wall -Wextra -Werror)
add_test(NAME TestTlsPipe COMMAND TestTlsPipe)

add_executable(TestSessionStore TestSessionStore.cpp)
target_link_libraries(TestSessionStore PRIVATE bazarish_server_shared)
target_compile_options(TestSessionStore PRIVATE -Wall -Wextra -Werror)
add_test(NAME TestSessionStore COMMAND TestSessionStore)
