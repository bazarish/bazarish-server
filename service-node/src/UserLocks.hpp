// Bazarish project (c) 2026
#pragma once

#include <map>
#include <memory>
#include <mutex>
#include <string>

namespace bazarish::service {

// One lock per account, held over everything that reads its records, goes to the network and
// writes them back. Taken before the stores' own locks; never two accounts at once.
class UserLocks {
public:
    class Held {
    public:
        explicit Held(std::shared_ptr<std::mutex> mutex);

    private:
        std::shared_ptr<std::mutex> mutex_;
        std::unique_lock<std::mutex> lock_;
    };

    Held hold(const std::string& user);
    // Those holding the account's lock and those waiting for it.
    long holders(const std::string& user);

private:
    std::mutex mutex_;
    std::map<std::string, std::weak_ptr<std::mutex>> locks_;
};

}  // namespace bazarish::service
