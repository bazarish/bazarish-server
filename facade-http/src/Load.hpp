// Bazarish project (c) 2026
#pragma once

#include <array>
#include <cstdint>
#include <mutex>

namespace bazarish::facade {

// What the facade is carrying right now, for the operator panel. Deliberately not
// a history: three counts and a gauge, sampled when someone looks, so nothing
// accumulates and nothing has to be pruned.
//
// One bucket per second for the last minute, one per minute for the last day (the
// hour is the last sixty of those). A bucket carries the stamp of the period it
// belongs to, so a stale one reads as zero with nobody sweeping it.
class Load {
public:
    struct Sample {
        std::uint64_t lastMinute = 0;
        std::uint64_t lastHour = 0;
        std::uint64_t lastDay = 0;
        std::uint64_t inFlight = 0;
        std::uint64_t total = 0;
    };

    // One request arriving; the returned guard counts it as in flight until it
    // goes out of scope.
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
        std::int64_t stamp = -1;  // the second (or minute) this bucket counts
        std::uint64_t count = 0;
    };

    mutable std::mutex mutex_;
    std::array<Bucket, kSecondsPerMinute> seconds_{};
    std::array<Bucket, kMinutesPerDay> minutes_{};
    std::uint64_t inFlight_ = 0;
    std::uint64_t total_ = 0;
};

}  // namespace bazarish::facade
