// Bazarish project (c) 2026
#pragma once

#include "LogRing.hpp"
#include "OpsGate.hpp"

#include <bazarish/HttpServer.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace bazarish::server {

inline constexpr std::chrono::seconds kLogWait{25};
inline constexpr std::size_t kLogLinesPerAnswer = 500;

struct LogFeedState;

// GET <path>?after=N answers the lines past N; with none yet it is held for one, up to the wait.
class LogFeed {
public:
    LogFeed(http::Server& ops, const std::string& path, std::shared_ptr<LogRing> ring,
        Refusal refusal, std::chrono::milliseconds wait = kLogWait);
    ~LogFeed();

    LogFeed(const LogFeed&) = delete;
    LogFeed& operator=(const LogFeed&) = delete;

private:
    const std::shared_ptr<LogRing> ring_;
    std::shared_ptr<LogFeedState> state_;
    std::uint64_t listener_ = 0;
};

}  // namespace bazarish::server
