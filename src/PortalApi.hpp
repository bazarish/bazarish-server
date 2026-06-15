// Bazarish project (c) 2026
#pragma once

#include "LoginChallenge.hpp"
#include "PortalSession.hpp"

#include <cstdint>
#include <memory>
#include <string>

namespace httplib {
class Server;
}

namespace bazarish::service {

struct PortalApiOptions {
    // This service node's fingerprint — the login challenge audience, so a
    // challenge issued here cannot be replayed against another portal.
    std::string audience;
    // Portal-local HMAC secrets (login challenge binding, session cookie).
    std::string challengeSecret;
    std::string sessionSecret;
    std::int64_t sessionTtlSeconds = 3600;
};

// The service node's web portal (browser-facing). This first slice serves the
// sign-in-with-key flow: GET /portal/login issues a challenge, POST
// /portal/login verifies the user's signed blob and sets a session cookie, and
// GET /portal/me reports the logged-in user. Registration, top-ups, payments
// and purchases are added on top.
class PortalApi {
public:
    explicit PortalApi(PortalApiOptions options);
    ~PortalApi();

    bool listen(const std::string& host, int port);
    int bindToAnyPort(const std::string& host);
    bool listenAfterBind();
    void stop();

private:
    void setupRoutes();

    PortalApiOptions options_;
    LoginChallenge login_;
    PortalSession session_;
    std::unique_ptr<httplib::Server> http_;
};

}  // namespace bazarish::service
