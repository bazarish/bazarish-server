// Bazarish project (c) 2026
#pragma once

#include <bazarish/Portal.hpp>

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace bazarish::service {

inline constexpr std::size_t kMaxAwaitedLogins = 1024;

class LoginMailbox {
public:
    explicit LoginMailbox(std::int64_t windowSeconds = kLoginWindowSeconds);

    void expect(const std::string& challenge, const std::string& token, std::int64_t now);

    std::string challengeOf(const std::string& nonce, std::int64_t now);

    bool deliver(const std::string& nonce, const std::string& challenge, const std::string& blob,
        std::int64_t now);

    enum class State {
        eWaiting,
        eSigned,
        eGone,
    };
    struct Claim {
        State state = State::eGone;
        std::string challenge;
        std::string blob;
    };
    Claim claim(const std::string& nonce, const std::string& token, std::int64_t now);

private:
    struct Awaited {
        std::string token;
        std::string challenge;
        std::string blob;
        std::int64_t since = 0;
    };

    void pruneLocked(std::int64_t now);

    std::int64_t windowSeconds_;
    std::mutex mutex_;
    std::unordered_map<std::string, Awaited> awaited_;
};

}  // namespace bazarish::service
