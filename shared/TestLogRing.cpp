// Bazarish project (c) 2026
#include "LogRing.hpp"
#include "TestUtil.hpp"

#include <bazarish/Log.hpp>

#include <cstdio>
#include <memory>
#include <string>

using bazarish::log::Level;
using bazarish::server::LogCapture;
using bazarish::server::LogPage;
using bazarish::server::LogRing;

namespace {

constexpr std::size_t kSmallRing = 3;
constexpr std::size_t kAll = 100;
constexpr std::int64_t kSomeMillis = 1700000000000;

}  // namespace

int main()
{
    {
        const LogRing empty(kSmallRing);
        const LogPage page = empty.after(0, kAll);
        CHECK(empty.last() == 0);
        CHECK(page.first == 1);
        CHECK(page.lines.empty());
        CHECK(!page.instance.empty());
        CHECK(page.instance != LogRing(kSmallRing).instance());
    }

    {
        LogRing ring(kSmallRing);
        int woken = 0;
        const std::uint64_t listener = ring.listen([&woken]() { ++woken; });
        ring.append(Level::eInfo, "one", kSomeMillis);
        ring.append(Level::eWarn, "two", kSomeMillis + 1);
        CHECK(woken == 2);

        const LogPage both = ring.after(0, kAll);
        CHECK(both.first == 1);
        CHECK(both.lines.size() == 2);
        CHECK(both.lines[0].seq == 1 && both.lines[0].text == "one");
        CHECK(both.lines[1].seq == 2 && both.lines[1].level == Level::eWarn);
        CHECK(both.lines[1].t == kSomeMillis + 1);
        CHECK(ring.after(1, kAll).lines.size() == 1);
        CHECK(ring.after(2, kAll).lines.empty());

        ring.append(Level::eError, "three", kSomeMillis);
        ring.append(Level::eDebug, "four", kSomeMillis);
        ring.append(Level::eInfo, "five", kSomeMillis);
        CHECK(ring.last() == 5);
        const LogPage kept = ring.after(0, kAll);
        CHECK(kept.first == 3);
        CHECK(kept.lines.size() == kSmallRing);
        CHECK(kept.lines.front().seq == 3 && kept.lines.back().seq == 5);

        const LogPage behind = ring.after(1, kAll);
        CHECK(behind.first > 1 + 1);
        CHECK(behind.lines.front().seq == behind.first);

        const LogPage capped = ring.after(0, 2);
        CHECK(capped.lines.size() == 2);
        CHECK(capped.lines.back().seq == 4);
        CHECK(ring.after(4, 2).lines.front().seq == 5);
        CHECK(ring.after(kAll, kAll).lines.empty());

        ring.unlisten(listener);
        ring.append(Level::eInfo, "six", kSomeMillis);
        CHECK(woken == 5);

        const nlohmann::json shown = bazarish::server::logPageJson(ring.after(5, kAll));
        CHECK(shown.at("instance") == ring.instance());
        CHECK(shown.at("first") == 4);
        CHECK(shown.at("lines").size() == 1);
        CHECK(shown.at("lines")[0].at("seq") == 6);
        CHECK(shown.at("lines")[0].at("level") == "info");
        CHECK(shown.at("lines")[0].at("text") == "six");
        CHECK(shown.at("lines")[0].at("t") == kSomeMillis);
    }

    {
        bazarish::log::setLevel(Level::eWarn);
        const auto ring = std::make_shared<LogRing>();
        {
            const LogCapture capture(ring);
            bazarish::log::warn("caught {}", 1);
            bazarish::log::info("under the level");
        }
        bazarish::log::error("after the capture");
        const LogPage page = ring->after(0, kAll);
        CHECK(page.lines.size() == 1);
        CHECK(page.lines[0].level == Level::eWarn);
        CHECK(page.lines[0].text == "caught 1");
        CHECK(page.lines[0].t > 0);
    }

    std::printf("TestLogRing OK\n");
    return 0;
}
