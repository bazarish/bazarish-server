// Bazarish project (c) 2026
#pragma once

#include "SubscriptionStore.hpp"

#include <bazarish/Bytes.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace httplib {
class Server;
}

namespace bazarish::service {

struct AccountApiOptions {
    // The messaging server this service node belongs to; subscription
    // certificates must name it.
    std::string serverFingerprint;
    // The server card returned to clients on subscribe (DER).
    Bytes serverCardDer;
    // Quota granted to a free subscription.
    std::uint64_t defaultQuotaBytes = 10 * 1024 * 1024;
    // Maximum subscription validity the server accepts.
    std::int64_t maxTermSeconds = 14 * 24 * 3600;
};

// The /v1/account/* HTTP API: subscriptions, aliases and alias resolution.
// Authenticated requests carry the caller's hybrid identity (see common
// Auth); a caller may only act on certificates naming its own UID.
class AccountApi {
public:
    AccountApi(SubscriptionStore& store, AccountApiOptions options);
    ~AccountApi();

    bool listen(const std::string& host, int port);
    int bindToAnyPort(const std::string& host);
    bool listenAfterBind();
    void stop();

private:
    void setupRoutes();

    SubscriptionStore& store_;
    const AccountApiOptions options_;
    std::unique_ptr<httplib::Server> http_;
};

}  // namespace bazarish::service
