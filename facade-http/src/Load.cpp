// Bazarish project (c) 2026
#include "Load.hpp"

namespace bazarish::facade {

Load::InFlight::InFlight(Load& load)
    : load_(load)
{
    const std::lock_guard<std::mutex> lock(load_.mutex_);
    ++load_.inFlight_;
}

Load::InFlight::~InFlight()
{
    const std::lock_guard<std::mutex> lock(load_.mutex_);
    if (load_.inFlight_ > 0) {
        --load_.inFlight_;
    }
}

void Load::record(const std::int64_t nowSeconds)
{
    const std::int64_t minute = nowSeconds / static_cast<std::int64_t>(kSecondsPerMinute);
    const std::lock_guard<std::mutex> lock(mutex_);
    ++total_;

    Bucket& second = seconds_[static_cast<std::size_t>(nowSeconds) % kSecondsPerMinute];
    if (second.stamp != nowSeconds) {
        second.stamp = nowSeconds;
        second.count = 0;
    }
    ++second.count;

    Bucket& perMinute = minutes_[static_cast<std::size_t>(minute) % kMinutesPerDay];
    if (perMinute.stamp != minute) {
        perMinute.stamp = minute;
        perMinute.count = 0;
    }
    ++perMinute.count;
}

Load::Sample Load::sample(const std::int64_t nowSeconds) const
{
    const std::int64_t minute = nowSeconds / static_cast<std::int64_t>(kSecondsPerMinute);
    const std::lock_guard<std::mutex> lock(mutex_);

    Sample sample;
    sample.inFlight = inFlight_;
    sample.total = total_;
    for (const Bucket& bucket : seconds_) {
        if (bucket.stamp > nowSeconds - static_cast<std::int64_t>(kSecondsPerMinute)
            && bucket.stamp <= nowSeconds) {
            sample.lastMinute += bucket.count;
        }
    }
    for (const Bucket& bucket : minutes_) {
        if (bucket.stamp > minute - static_cast<std::int64_t>(kMinutesPerDay)
            && bucket.stamp <= minute) {
            sample.lastDay += bucket.count;
            if (bucket.stamp > minute - static_cast<std::int64_t>(kMinutesPerHour)) {
                sample.lastHour += bucket.count;
            }
        }
    }
    return sample;
}

}  // namespace bazarish::facade
