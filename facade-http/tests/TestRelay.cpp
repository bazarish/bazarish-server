// Bazarish project (c) 2026
#include "Relay.hpp"

#include "TestUtil.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <algorithm>
#include <mutex>
#include <thread>

namespace {

constexpr char kFiller = 'x';
constexpr auto kQuickerThanDrain = std::chrono::milliseconds(bazarish::facade::kDrainMillis / 4);

class TalkativeStream {
public:
    std::size_t readSome(const bazarish::ByteBuffer buffer)
    {
        if (closed_.load()) {
            return 0;
        }
        std::fill(buffer.begin(), buffer.end(), kFiller);
        return buffer.size();
    }

    void writeAll(bazarish::ByteView) {}

    void close() { closed_.store(true); }

private:
    std::atomic<bool> closed_{false};
};

class SilentStream {
public:
    std::size_t readSome(bazarish::ByteBuffer)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        closing_.wait(lock, [this]() { return closed_; });
        return 0;
    }

    void writeAll(bazarish::ByteView) {}

    void close()
    {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            closed_ = true;
        }
        closing_.notify_all();
    }

private:
    std::mutex mutex_;
    std::condition_variable closing_;
    bool closed_ = false;
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
    CHECK(::close(ends[0]) == 0);

    int quiet[2] = {-1, -1};
    CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, quiet) == 0);
    SilentStream silent;
    const auto stopping = std::chrono::steady_clock::now();
    std::thread relaying([&silent, &quiet]() { bazarish::facade::relay(silent, quiet[0]); });
    silent.close();
    CHECK(::shutdown(quiet[0], SHUT_RDWR) == 0);
    relaying.join();
    CHECK(std::chrono::steady_clock::now() - stopping < kQuickerThanDrain);
    CHECK(::close(quiet[0]) == 0);
    CHECK(::close(quiet[1]) == 0);
    return 0;
}
