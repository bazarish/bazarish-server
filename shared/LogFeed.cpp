// Bazarish project (c) 2026
#include "LogFeed.hpp"

#include <bazarish/Errors.hpp>
#include <bazarish/HttpResponses.hpp>

#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <charconv>
#include <map>
#include <optional>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace asio = boost::asio;

namespace bazarish::server {

struct LogFeedState {
    LogFeedState(const asio::any_io_executor& executor, std::shared_ptr<LogRing> logs,
        const std::chrono::milliseconds held)
        : strand(asio::make_strand(executor))
        , ring(std::move(logs))
        , wait(held)
    {
    }

    struct Held {
        std::uint64_t after = 0;
        http::Responder respond;
        std::unique_ptr<asio::steady_timer> timer;
    };

    asio::strand<asio::any_io_executor> strand;
    const std::shared_ptr<LogRing> ring;
    const std::chrono::milliseconds wait;
    std::atomic<std::size_t> holding{0};
    std::map<std::uint64_t, Held> held;
    std::uint64_t nextHeld = 0;
};

namespace {

constexpr int kBadRequest = 400;

http::Response pageResponse(const LogPage& page)
{
    // i2pd's lines are not promised to be UTF-8.
    return http::Response{200, "application/json", {},
        logPageJson(page).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace)};
}

std::optional<std::uint64_t> afterIn(const std::string& text)
{
    if (text.empty()) {
        return 0;
    }
    std::uint64_t value = 0;
    const char* const end = text.data() + text.size();
    const std::from_chars_result parsed = std::from_chars(text.data(), end, value);
    if (parsed.ec != std::errc() || parsed.ptr != end) {
        return std::nullopt;
    }
    return value;
}

void answerReady(LogFeedState& state)
{
    for (auto it = state.held.begin(); it != state.held.end();) {
        const LogPage page = state.ring->after(it->second.after, kLogLinesPerAnswer);
        if (page.lines.empty()) {
            ++it;
            continue;
        }
        it->second.timer->cancel();
        it->second.respond(pageResponse(page));
        it = state.held.erase(it);
        --state.holding;
    }
}

void hold(const std::shared_ptr<LogFeedState>& state, const std::uint64_t after,
    http::Responder respond)
{
    // Counted before the look, so a line landing in between always posts a wake.
    ++state->holding;
    const LogPage page = state->ring->after(after, kLogLinesPerAnswer);
    if (!page.lines.empty()) {
        --state->holding;
        respond(pageResponse(page));
        return;
    }
    const std::uint64_t id = ++state->nextHeld;
    auto timer = std::make_unique<asio::steady_timer>(state->strand, state->wait);
    timer->async_wait([state, id](const boost::system::error_code&) {
        const auto found = state->held.find(id);
        if (found == state->held.end()) {
            return;
        }
        found->second.respond(
            pageResponse(state->ring->after(found->second.after, kLogLinesPerAnswer)));
        state->held.erase(found);
        --state->holding;
    });
    state->held.emplace(id, LogFeedState::Held{after, std::move(respond), std::move(timer)});
}

}  // namespace

LogFeed::LogFeed(http::Server& ops, const std::string& path, std::shared_ptr<LogRing> ring,
    Refusal refusal, const std::chrono::milliseconds wait)
    : ring_(std::move(ring))
{
    if (!ring_) {
        throw std::invalid_argument("a log feed needs a ring to read");
    }
    state_ = std::make_shared<LogFeedState>(ops.executor(), ring_, wait);
    const std::weak_ptr<LogFeedState> watched = state_;
    listener_ = ring_->listen([watched]() {
        const std::shared_ptr<LogFeedState> state = watched.lock();
        if (state && state->holding.load() > 0) {
            asio::post(state->strand, [state]() { answerReady(*state); });
        }
    });
    ops.getAsync(path,
        [state = state_, refusal = std::move(refusal)](const http::Request& request,
            http::Responder respond) -> std::optional<http::Response> {
            if (std::optional<http::Response> refused = refusal(request); refused.has_value()) {
                return refused;
            }
            const std::optional<std::uint64_t> after = afterIn(request.query("after"));
            if (!after.has_value()) {
                return http::errorResponse(
                    kBadRequest, ErrorCode::eRequestFailed, "\"after\" is a line number");
            }
            const LogPage page = state->ring->after(*after, kLogLinesPerAnswer);
            if (!page.lines.empty() || *after > state->ring->last()) {
                return pageResponse(page);
            }
            asio::post(state->strand, [state, after = *after, respond = std::move(respond)]() {
                hold(state, after, respond);
            });
            return std::nullopt;
        });
}

LogFeed::~LogFeed()
{
    ring_->unlisten(listener_);
}

}  // namespace bazarish::server
