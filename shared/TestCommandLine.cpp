// Bazarish project (c) 2026
#include "CommandLine.hpp"

#include "TestUtil.hpp"

#include <cstdio>

using bazarish::server::configArgument;

int main()
{
    int usages = 0;
    const auto usage = [&usages]() { ++usages; };

    const char* const version[] = {"x", "--version"};
    CHECK(std::get<int>(configArgument(2, version, "x 1.0", usage)) == 0);
    CHECK(usages == 0);

    const char* const config[] = {"x", "--config", "/etc/x.json"};
    CHECK(std::get<std::filesystem::path>(configArgument(3, config, "x 1.0", usage))
        == "/etc/x.json");
    CHECK(usages == 0);

    const char* const bare[] = {"x"};
    CHECK(std::get<int>(configArgument(1, bare, "x 1.0", usage)) == bazarish::server::kUsageExitCode);
    const char* const dangling[] = {"x", "--config"};
    CHECK(std::get<int>(configArgument(2, dangling, "x 1.0", usage)) == bazarish::server::kUsageExitCode);
    const char* const extra[] = {"x", "--config", "a", "b"};
    CHECK(std::get<int>(configArgument(4, extra, "x 1.0", usage)) == bazarish::server::kUsageExitCode);
    const char* const other[] = {"x", "--settings", "a"};
    CHECK(std::get<int>(configArgument(3, other, "x 1.0", usage)) == bazarish::server::kUsageExitCode);
    CHECK(usages == 4);

    std::printf("TestCommandLine passed\n");
    return 0;
}
