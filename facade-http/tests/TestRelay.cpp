// Bazarish project (c) 2026
#include "Relay.hpp"

#include "TestUtil.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>

namespace {

constexpr char kFiller = 'x';
constexpr auto kQuickerThanDrain = std::chrono::milliseconds(bazarish::facade::kDrainMillis / 4);

class TalkativeStream {
public:
    std::size_t readSome(void* buffer, const std::size_t size)
    {
        if (closed_.load()) {
            return 0;
        }
        std::memset(buffer, kFiller, size);
        return size;
    }

    void writeAll(const void*, std::size_t) {}

    void close() { closed_.store(true); }

private:
    std::atomic<bool> closed_{false};
};

}  // namespace

int main()
{
    int ends[2] = {-1, -1};
    CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, ends) == 0);
    ::close(ends[1]);

    TalkativeStream peer;
    const auto started = std::chrono::steady_clock::now();
    bazarish::facade::relay(peer, ends[0]);
    CHECK(std::chrono::steady_clock::now() - started < kQuickerThanDrain);
    return 0;
}
