// Bazarish project (c) 2026
#pragma once

#include <array>
#include <cstdint>
#include <mutex>

namespace bazarish::facade {

class Load {
public:
    struct Sample {
        std::uint64_t lastMinute = 0;
        std::uint64_t lastHour = 0;
        std::uint64_t lastDay = 0;
        std::uint64_t inFlight = 0;
        std::uint64_t total = 0;
    };

    class InFlight {
    public:
        explicit InFlight(Load& load);
        ~InFlight();
        InFlight(const InFlight&) = delete;
        InFlight& operator=(const InFlight&) = delete;

    private:
        Load& load_;
    };

    void record(std::int64_t nowSeconds);
    Sample sample(std::int64_t nowSeconds) const;

private:
    static constexpr std::size_t kSecondsPerMinute = 60;
    static constexpr std::size_t kMinutesPerDay = 24 * 60;
    static constexpr std::size_t kMinutesPerHour = 60;

    struct Bucket {
        std::int64_t stamp = -1;
        std::uint64_t count = 0;
    };

    mutable std::mutex mutex_;
    std::array<Bucket, kSecondsPerMinute> seconds_{};
    std::array<Bucket, kMinutesPerDay> minutes_{};
    std::uint64_t inFlight_ = 0;
    std::uint64_t total_ = 0;
};

}  // namespace bazarish::facade
