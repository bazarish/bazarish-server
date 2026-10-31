// Bazarish project (c) 2026
#include "Restart.hpp"

#include <cstdio>
#include <cstdlib>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>

using namespace bazarish;

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
            CHECK(stops.load() == 0);
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

    std::printf("TestRestart: all checks passed\n");
    return 0;
}
