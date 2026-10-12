// Bazarish project (c) 2026
#include "Health.hpp"

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

#include <nlohmann/json.hpp>

#include <string>

using namespace bazarish;

int main()
{
    const health::MemoryUsage memory = health::processMemoryUsage();
    CHECK(memory.current > 0);
    CHECK(memory.peak >= memory.current);

    const std::string text = health::reportJson("server-core", "0.0.2", 1000, 1123);
    const nlohmann::json report = nlohmann::json::parse(text);
    CHECK(report.at("service").get<std::string>() == "server-core");
    CHECK(report.at("version").get<std::string>() == "0.0.2");
    CHECK(report.at("uptime").get<std::int64_t>() == 123);
    CHECK(report.at("ramBytes").get<std::uint64_t>() == memory.current
        || report.at("ramBytes").get<std::uint64_t>() > 0);
    CHECK(report.contains("ramPeakBytes"));

    std::printf("TestHealth: all checks passed\n");
    return 0;
}
