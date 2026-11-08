// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace bazarish::health {

struct MemoryUsage {
    std::uint64_t current = 0;
    std::uint64_t peak = 0;
};

MemoryUsage processMemoryUsage();
// What the files under a directory hold; one that goes while it is walked counts nothing.
std::uint64_t treeBytes(const std::filesystem::path& directory);

std::string reportJson(const std::string& service, const std::string& version,
    std::int64_t startedAt, std::int64_t now, const std::string& extrasJson = {});

}  // namespace bazarish::health
