// Bazarish project (c) 2026
#pragma once

#include <utility>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/steady_timer.hpp>

#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace bazarish::server {

// Wakes long-poll waiters when something lands for a user.
//
// A waiter is an asio timer, not a thread: hundreds of clients holding a request
// open cost hundreds of timers and no threads at all, which is the whole point of
// serving this path asynchronously. A notification cancels the user's timers; the
// handler then re-reads the mailbox and answers. A waiter that nobody wakes
// expires on its own, so a client that has been forgotten still gets an answer.
class EventGate {
public:
    // Suspends until something arrives for `user` or `timeout` passes, then runs
    // `handler`. Safe to call from any thread; the handler runs on `executor`.
    template <class Handler>
    void wait(const boost::asio::any_io_executor& executor, const std::string& user,
        std::chrono::seconds timeout, Handler handler)
    {
        const std::shared_ptr<boost::asio::steady_timer> timer
            = std::make_shared<boost::asio::steady_timer>(executor, timeout);
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            waiters_[user].push_back(timer);
        }
        timer->async_wait([this, user, timer, handler = std::move(handler)](
                              const boost::system::error_code&) mutable {
            forget(user, timer);
            handler();
        });
    }

    // Something landed for this user: wake everyone waiting on it.
    void notify(const std::string& user);

    // Waiters currently held, for the operator's status view.
    std::size_t waiting() const;

private:
    void forget(const std::string& user, const std::shared_ptr<boost::asio::steady_timer>& timer);

    mutable std::mutex mutex_;
    std::map<std::string, std::vector<std::shared_ptr<boost::asio::steady_timer>>> waiters_;
};

}  // namespace bazarish::server
