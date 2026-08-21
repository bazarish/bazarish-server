// Bazarish project (c) 2026
#pragma once

#include "GrantStore.hpp"
#include "NodeSettings.hpp"

#include <bazarish/Captcha.hpp>
#include <bazarish/WebAssets.hpp>
#include <bazarish/LoginChallenge.hpp>
#include <bazarish/PortalSession.hpp>

#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>

namespace bazarish::http {
class Server;
}

namespace bazarish::service {

struct PortalApiOptions {
    // This service node's fingerprint - the login challenge audience, so a
    // challenge issued here cannot be replayed against another portal.
    std::string audience;
    // The server descriptor string (bazarish://server?...) shown in the cabinet
    // so a signed-in user can copy it into their client. Empty hides the section.
    std::string serverDescriptor;
    // Portal-local HMAC secrets (login challenge binding, session cookie).
    std::string challengeSecret;
    std::string sessionSecret;
    std::int64_t sessionTtlSeconds = 3600;
    // The subscription granted on registration. Every account gets the same one:
    // nothing on this node is for sale. The initial value; an operator can
    // change it while the node runs (see settings).
    std::uint64_t defaultQuotaBytes = 20 * 1024 * 1024;
    std::int64_t freeSubscriptionTermSeconds = 14 * 24 * 3600;
    // When false, registration is open to any logged-in (sign-in-with-key) user
    // without solving a captcha. Advertised to clients via the discovery
    // endpoint's freeRegistration.captcha flag, so the two cannot disagree.
    bool requireCaptcha = true;
    // Whether an account this node registers still waits for an operator before
    // it is served. The page has to say so at registration: the account is only
    // marked pending once a client redeems the grant, and until then nothing
    // else would tell the user their messages are not flowing yet.
    bool requiresApproval = false;
    // Shown to a user whose account is created frozen on a moderated node: how
    // to reach the operator to finish registration. Empty on an open node.
    std::string registrationMessage;
    // Where the portal's web files live (page shell, stylesheet, logo, fonts).
    std::filesystem::path assetsDirectory;
    // The live knobs, shared with the account API. When null (tests), the values
    // above are taken as the settings.
    std::shared_ptr<NodeSettings> settings;
};

// The service node's web portal (browser-facing). It exposes two faces on one
// HTTP server, sharing all state:
//   * a JSON API under /portal/* for programmatic clients (sign-in-with-key
//     login, captcha, register);
//   * a server-rendered, JS-free page at / so a user can onboard from a plain
//     browser. The private key never enters the browser: the page shows a
//     challenge the user signs in their client and pastes back.
// There is no account area to visit afterwards: the page is a two-step flow -
// prove the key, read the captcha - and the second step is the registration.
class PortalApi {
public:
    PortalApi(PortalApiOptions options, Captcha& captcha, GrantStore& grants);
    ~PortalApi();

    bool listen(const std::string& host, int port);
    int bindToAnyPort(const std::string& host);
    bool listenAfterBind();
    void stop();

private:
    // Binds on a chosen port (0 lets the kernel pick) and starts serving.
    int bindToAnyPort(const std::string& host, int port);
    void setupRoutes();
    // Registers the browser-facing routes (the page and its files).
    void setupWebRoutes();
    // The portal's one page, in whatever state the visitor is in. `error` is
    // shown on the step the visitor is standing on, empty when there is none.
    std::string homePage(const std::string& user, const std::string& error);

    // What the operator has set, live.
    NodeSettings::Values settings() const { return settings_->get(); }

    PortalApiOptions options_;
    std::shared_ptr<NodeSettings> settings_;
    WebAssets assets_;
    Captcha& captcha_;
    GrantStore& grants_;
    LoginChallenge login_;
    PortalSession session_;
    std::unique_ptr<bazarish::http::Server> http_;

    // listenAfterBind() parks the caller's thread here until stop() releases it.
    std::mutex stopMutex_;
    std::condition_variable stopCv_;
    bool stopping_ = false;
};

}  // namespace bazarish::service
