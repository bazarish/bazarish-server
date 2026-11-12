// Bazarish project (c) 2026
#pragma once

#include <utility>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace bazarish::server {

class EventGate {
public:
    // No deadline: a wait ends when its user is told, or when the same client waits again.
    template <class Handler>
    void wait(const boost::asio::any_io_executor& executor, const std::string& user,
        const std::string& client, Handler handler)
    {
        const std::shared_ptr<boost::asio::steady_timer> timer
            = std::make_shared<boost::asio::steady_timer>(
                executor, boost::asio::steady_timer::time_point::max());
        std::vector<std::shared_ptr<boost::asio::steady_timer>> superseded;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            if (early_.erase(user) > 0) {
                boost::asio::post(executor, std::move(handler));
                return;
            }
            std::vector<Waiter>& held = waiters_[user];
            std::erase_if(held, [&client, &superseded](const Waiter& waiter) {
                if (waiter.client != client) {
                    return false;
                }
                if (const std::shared_ptr<boost::asio::steady_timer> alive = waiter.timer.lock()) {
                    superseded.push_back(alive);
                }
                return true;
            });
            held.push_back({client, timer});
        }
        for (const std::shared_ptr<boost::asio::steady_timer>& earlier : superseded) {
            earlier->cancel();
        }
        timer->async_wait([this, user, timer, handler = std::move(handler)](
                              const boost::system::error_code&) mutable {
            forget(user, timer);
            handler();
        });
    }

    void notify(const std::string& user);

    std::size_t waiting() const;

private:
    struct Waiter {
        std::string client;
        // Weak: a timer is its handler's, so it goes with its io_context and never outlives it.
        std::weak_ptr<boost::asio::steady_timer> timer;
    };

    void forget(const std::string& user, const std::shared_ptr<boost::asio::steady_timer>& timer);

    mutable std::mutex mutex_;
    std::map<std::string, std::vector<Waiter>> waiters_;
    // Told while nobody waited: the next wait ends at once rather than miss it.
    std::set<std::string> early_;
};

}  // namespace bazarish::server
