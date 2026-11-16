// Bazarish project (c) 2026
#include "Restart.hpp"
#include "TestUtil.hpp"

#include <bazarish/HttpServer.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>

using namespace bazarish;

namespace {

constexpr std::size_t kLongAnswerBytes = 8 * 1024 * 1024;
constexpr int kSmallReceiveBuffer = 4096;
constexpr int kReadGiveUpSeconds = 10;
// Longer than the grace a restart once gave its answer before it stopped the server.
constexpr std::chrono::milliseconds kSlowReaderPause{1500};
constexpr std::size_t kReadChunk = 64 * 1024;
constexpr char kHeadEnd[] = "\r\n\r\n";

std::string askSlowly(const int port, const std::string& request)
{
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    CHECK(::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &kSmallReceiveBuffer, sizeof kSmallReceiveBuffer)
        == 0);
    const timeval giveUp{kReadGiveUpSeconds, 0};
    CHECK(::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &giveUp, sizeof giveUp) == 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<std::uint16_t>(port));
    CHECK(::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    CHECK(::connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof address) == 0);
    CHECK(::send(fd, request.data(), request.size(), 0) == static_cast<ssize_t>(request.size()));
    std::this_thread::sleep_for(kSlowReaderPause);
    std::string heard;
    std::string chunk(kReadChunk, '\0');
    for (;;) {
        const ssize_t got = ::recv(fd, chunk.data(), chunk.size(), 0);
        if (got <= 0) {
            break;
        }
        heard.append(chunk.data(), static_cast<std::size_t>(got));
    }
    CHECK(::close(fd) == 0);
    return heard;
}

}  // namespace

int main()
{
    {
        std::atomic<int> stops{0};
        {
            RestartSwitch restart([&stops]() { stops.fetch_add(1); });
            CHECK(!restart.requested());
        }
        CHECK(stops.load() == 0);
    }

    {
        std::atomic<int> stops{0};
        std::atomic<bool> stoppedByAnotherThread{false};
        const std::thread::id handler = std::this_thread::get_id();
        {
            RestartSwitch restart([&]() {
                stoppedByAnotherThread.store(std::this_thread::get_id() != handler);
                stops.fetch_add(1);
            });
            restart.request();
            CHECK(restart.requested());
        }
        CHECK(stops.load() == 1);
        CHECK(stoppedByAnotherThread.load());
    }

    {
        std::atomic<int> stops{0};
        {
            RestartSwitch restart([&stops]() { stops.fetch_add(1); });
            restart.request();
            restart.request();
            restart.request();
        }
        CHECK(stops.load() == 1);
    }

    {
        http::Server server(http::Server::Options{});
        RestartSwitch restart([&server]() { server.stop(); });
        const std::string answer(kLongAnswerBytes, 'r');
        server.post("/restart", [&restart, &answer](const http::Request&) {
            restart.request();
            return http::Response{200, "text/plain", {}, answer};
        });
        const int port = server.start();
        CHECK(port > 0);
        const std::string heard = askSlowly(port,
            "POST /restart HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n"
            "Connection: close\r\n\r\n");
        const std::size_t head = heard.find(kHeadEnd);
        CHECK(head != std::string::npos);
        CHECK(heard.size() - head - (sizeof kHeadEnd - 1) == answer.size());
        CHECK(restart.requested());
    }

    std::printf("TestRestart: all checks passed\n");
    return 0;
}
