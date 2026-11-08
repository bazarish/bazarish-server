// Bazarish project (c) 2026
#include "Health.hpp"

#include <bazarish/JsonRead.hpp>

#include <nlohmann/json.hpp>

#include <fstream>
#include <limits>
#include <stdexcept>
#include <string>
#include <system_error>

namespace bazarish::health {

namespace {

constexpr const char* kStatusFile = "/proc/self/status";
// proc(5) gives the memory fields in kibibytes.
constexpr std::uint64_t kKibibyte = 1024;

std::uint64_t statusFieldBytes(const std::string& field)
{
    std::ifstream status(kStatusFile);
    if (!status) {
        throw std::runtime_error(std::string("health: cannot read ") + kStatusFile);
    }
    std::string label;
    while (status >> label) {
        if (label == field) {
            std::uint64_t kib = 0;
            std::string unit;
            if (!(status >> kib >> unit)) {
                throw std::runtime_error("health: " + field + " does not read as a size");
            }
            return kib * kKibibyte;
        }
        status.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }
    throw std::runtime_error("health: " + std::string(kStatusFile) + " names no " + field);
}

}  // namespace

MemoryUsage processMemoryUsage()
{
    MemoryUsage usage;
    usage.current = statusFieldBytes("VmRSS:");
    usage.peak = statusFieldBytes("VmHWM:");
    return usage;
}

std::uint64_t treeBytes(const std::filesystem::path& directory)
{
    std::uint64_t bytes = 0;
    std::error_code failure;
    for (std::filesystem::recursive_directory_iterator walk(directory, failure), end;
         !failure && walk != end; walk.increment(failure)) {
        std::error_code gone;
        if (walk->is_regular_file(gone)) {
            const std::uintmax_t size = walk->file_size(gone);
            bytes += gone ? 0 : size;
        }
    }
    if (failure) {
        throw std::runtime_error(
            "health: cannot walk " + directory.string() + ": " + failure.message());
    }
    return bytes;
}

std::string reportJson(const std::string& service, const std::string& version,
    const std::int64_t startedAt, const std::int64_t now, const std::string& extrasJson)
{
    const MemoryUsage memory = processMemoryUsage();
    nlohmann::json report = {
        {"service", service},
        {"version", version},
        {"uptime", now - startedAt},
        {"ramBytes", memory.current},
        {"ramPeakBytes", memory.peak},
    };
    if (!extrasJson.empty()) {
        report.update(bazarish::parseJson(extrasJson));
    }
    return report.dump();
}

}  // namespace bazarish::health
