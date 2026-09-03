// Bazarish project (c) 2026
#pragma once

#include "GrantStore.hpp"
#include "NodeSettings.hpp"

#include <bazarish/Captcha.hpp>
#include <bazarish/WebAssets.hpp>
#include <bazarish/LoginChallenge.hpp>
#include <bazarish/PortalSession.hpp>

#include <condition_variable>
#include <functional>
#include <optional>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <map>
#include <string>

namespace bazarish::http {
class Server;
}

namespace bazarish::service {

struct PortalApiOptions {
    // This service node's fingerprint: part of the server descriptor a client
    // pastes to connect, and shown in the cabinet.
    std::string serverFingerprint;
    // Who this portal says it is when it asks a user to sign in. The client
    // shows these words before signing, so they are what a user compares with
    // the address bar; the challenge is bound to them, so a challenge issued
    // here cannot be replayed against another portal.
    LoginConsumer consumer;
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
    std::uint64_t defaultQuotaBytes = 50 * 1024 * 1024;
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
    // Where this node's messaging server keeps its reseed archive, on the private
    // channel (e.g. "http://127.0.0.1:8420/internal/i2pseeds.su3"). The portal
    // publishes it because the portal is what faces the clearnet: a client needs
    // the archive before it has I2P, so it cannot come through a facade. Empty
    // means this node publishes no reseed, which is a fair choice - an operator
    // may point their descriptor at reseeds that have nothing to do with them.
    std::string reseedArchiveUrl;
    // Where the portal's web files live (page shell, stylesheet, logo, fonts).
    std::filesystem::path assetsDirectory;
    // The live knobs, shared with the account API. When null (tests), the values
    // above are taken as the settings.
    std::shared_ptr<NodeSettings> settings;

    // What the messaging server holds for an account - the mailbox and the
    // devices collecting it - which the node does not know. Empty (or an empty
    // answer) leaves the page saying so rather than inventing a number.
    struct Usage {
        std::uint64_t usedBytes = 0;
        std::uint64_t quotaBytes = 0;
        std::size_t devices = 0;
    };
    std::function<std::optional<Usage>(const std::string& user)> accountUsage;

    // Tears an account down at its owner's request: the same end as unsubscribing
    // from a client, reachable by someone who only has a browser.
    std::function<void(const std::string& user)> deleteAccount;
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
    // The reseed archive as this portal last had it from the messaging server,
    // and when. Held briefly: the archive itself is repacked no more than hourly,
    // so asking more often would only move bytes.
    std::string reseedArchive();
    std::mutex reseedMutex_;
    std::string reseedSu3_;
    std::int64_t reseedFetchedAt_ = 0;

    // Binds on a chosen port (0 lets the kernel pick) and starts serving.
    int bindToAnyPort(const std::string& host, int port);
    void setupRoutes();
    // Registers the browser-facing routes (the page and its files).
    void setupWebRoutes();
    // The portal's one page, in whatever state the visitor is in. `error` is
    // shown on the step the visitor is standing on, empty when there is none.
    std::string homePage(const std::string& user, const std::string& error);
    // The values an account page fills in, whatever state the account is in.
    std::map<std::string, std::string> accountValues(const std::string& user,
        const std::optional<GrantStore::SubscriptionGrant>& subscription);

    // What the operator has set, live.
    NodeSettings::Values settings() const { return settings_->get(); }

    // The challenge issuer, holding whatever words the operator has set for this
    // portal now rather than the ones it was started with.
    LoginChallenge& login();

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
