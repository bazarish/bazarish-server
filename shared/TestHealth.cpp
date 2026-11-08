// Bazarish project (c) 2026
#include "Health.hpp"
#include "TestUtil.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <cstdlib>

#include <nlohmann/json.hpp>

#include <string>

using namespace bazarish;

namespace {

constexpr std::size_t kFileBytes = 1000;

}  // namespace

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
    CHECK(report.at("ramBytes").get<std::uint64_t>() > 0);
    CHECK(report.contains("ramPeakBytes"));

    const std::filesystem::path tree = testutil::freshDir("health-tree");
    std::filesystem::create_directories(tree / "inner");
    std::ofstream(tree / "a.bin") << std::string(kFileBytes, 'a');
    std::ofstream(tree / "inner" / "b.bin") << std::string(kFileBytes * 2, 'b');
    CHECK(health::treeBytes(tree) == kFileBytes * 3);
    std::filesystem::remove_all(tree);
    CHECK_THROWS(health::treeBytes(tree));

    std::printf("TestHealth: all checks passed\n");
    return 0;
}
