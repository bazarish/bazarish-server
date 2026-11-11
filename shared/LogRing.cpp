// Bazarish project (c) 2026
#include "LogRing.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Clock.hpp>

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace bazarish::server {

namespace {

constexpr std::size_t kInstanceBytes = 8;

}  // namespace

nlohmann::json logPageJson(const LogPage& page)
{
    nlohmann::json lines = nlohmann::json::array();
    for (const LogLine& line : page.lines) {
        lines.push_back({
            {"seq", line.seq},
            {"t", line.t},
            {"level", std::string(log::levelName(line.level))},
            {"text", line.text},
        });
    }
    return {{"instance", page.instance}, {"first", page.first}, {"lines", lines}};
}

LogRing::LogRing(const std::size_t capacity)
    : capacity_(capacity)
    , instance_(toHex(randomBytes(kInstanceBytes)))
{
    if (capacity_ == 0) {
        throw std::invalid_argument("a log ring keeps at least one line");
    }
}

void LogRing::append(
    const log::Level level, const std::string_view text, const std::int64_t unixMillis)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    ++last_;
    lines_.push_back(LogLine{last_, unixMillis, level, std::string(text)});
    while (lines_.size() > capacity_) {
        lines_.pop_front();
    }
    for (const auto& [id, listener] : listeners_) {
        listener();
    }
}

LogPage LogRing::after(const std::uint64_t seq, const std::size_t most) const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    LogPage page;
    page.instance = instance_;
    page.first = lines_.empty() ? last_ + 1 : lines_.front().seq;
    if (seq >= last_) {
        return page;
    }
    const std::uint64_t from = std::max(seq + 1, page.first);
    for (std::size_t at = static_cast<std::size_t>(from - page.first);
         at < lines_.size() && page.lines.size() < most; ++at) {
        page.lines.push_back(lines_[at]);
    }
    return page;
}

std::uint64_t LogRing::last() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return last_;
}

const std::string& LogRing::instance() const
{
    return instance_;
}

std::uint64_t LogRing::listen(Listener listener)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const std::uint64_t id = ++nextListener_;
    listeners_.emplace(id, std::move(listener));
    return id;
}

void LogRing::unlisten(const std::uint64_t id)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    listeners_.erase(id);
}

LogCapture::LogCapture(std::shared_ptr<LogRing> ring)
{
    if (!ring) {
        throw std::invalid_argument("a log capture needs a ring to write into");
    }
    log::setTap([ring = std::move(ring)](const log::Level level, const std::string_view,
                    const std::string_view message) { ring->append(level, message, nowMillis()); });
}

LogCapture::~LogCapture()
{
    log::setTap({});
}

}  // namespace bazarish::server
