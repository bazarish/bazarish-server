// Bazarish project (c) 2026
#pragma once

#include <bazarish/Log.hpp>

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace bazarish::server {

inline constexpr std::size_t kLogRingLines = 2000;

struct LogLine {
    std::uint64_t seq = 0;
    std::int64_t t = 0;
    log::Level level = log::Level::eInfo;
    std::string text;
};

struct LogPage {
    std::string instance;
    std::uint64_t first = 0;
    std::vector<LogLine> lines;
};

nlohmann::json logPageJson(const LogPage& page);

class LogRing {
public:
    using Listener = std::function<void()>;

    explicit LogRing(std::size_t capacity = kLogRingLines);

    void append(log::Level level, std::string_view text, std::int64_t unixMillis);
    LogPage after(std::uint64_t seq, std::size_t most) const;
    std::uint64_t last() const;
    const std::string& instance() const;

    // Runs under the ring's lock after every line, so it must neither log nor call the ring.
    std::uint64_t listen(Listener listener);
    void unlisten(std::uint64_t id);

private:
    const std::size_t capacity_;
    const std::string instance_;
    mutable std::mutex mutex_;
    std::deque<LogLine> lines_;
    std::uint64_t last_ = 0;
    std::map<std::uint64_t, Listener> listeners_;
    std::uint64_t nextListener_ = 0;
};

class LogCapture {
public:
    explicit LogCapture(std::shared_ptr<LogRing> ring);
    ~LogCapture();

    LogCapture(const LogCapture&) = delete;
    LogCapture& operator=(const LogCapture&) = delete;
};

}  // namespace bazarish::server
