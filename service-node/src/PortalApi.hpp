// Bazarish project (c) 2026
#pragma once

#include "GrantStore.hpp"
#include "Messages.hpp"
#include "NodeSettings.hpp"
#include "OperatorPush.hpp"

#include <bazarish/LoginChallenge.hpp>
#include <bazarish/PortalSession.hpp>
#include <Restart.hpp>

#include <bazarish/WebAssets.hpp>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>

namespace bazarish::http {
class Server;
}

namespace bazarish::service {

struct PortalApiOptions {
    // This service node's fingerprint: part of the server descriptor a client
    // pastes to connect, and shown in the cabinet.
    std::string serverFingerprint;
    // Portal-local HMAC secrets (login challenge binding, session cookie).
    std::string challengeSecret;
    std::string sessionSecret;
    std::int64_t sessionTtlSeconds = 3600;
    // Where this node's messaging server keeps its reseed archive, on the private
    // channel (e.g. "http://127.0.0.1:8420/internal/i2pseeds.su3"). The portal
    // publishes it because the portal is what faces the clearnet: a client needs
    // the archive before it has I2P, so it cannot come through a facade. Empty
    // means this node publishes no reseed, which is a fair choice - an operator
    // may point their descriptor at reseeds that have nothing to do with them.
    std::string reseedArchiveUrl;
    // Where the portal's web files live (page shell, stylesheet, logo, fonts).
    std::filesystem::path assetsDirectory;
    // The live knobs, shared with the account API so the two cannot disagree: the
    // quota a registration grants, whether it waits for an operator, what it is
    // told meanwhile, the words a login is signed under and the addresses the
    // descriptor is built from. Required - there is no second place any of it is
    // kept.
    std::shared_ptr<NodeSettings> settings;

    // What the messaging server holds for this account, which the node does not
    // know. Empty (or an empty answer) leaves the page saying so rather than
    // inventing a number.
    std::function<std::optional<MailboxUsage>(const std::string& user)> accountUsage;

    // Tears an account down at its owner's request: the same end as unsubscribing
    // from a client, reachable by someone who only has a browser.
    std::function<void(const std::string& user)> deleteAccount;
};

// The service node's web portal (browser-facing). It exposes two faces on one
// HTTP server, sharing all state:
//   * a JSON API under /portal/* for programmatic clients (sign-in-with-key
//     login, register);
//   * a server-rendered, JS-free page at / so a user can onboard from a plain
//     browser. The private key never enters the browser: the page shows a
//     challenge the user signs in their client and pastes back.
// There is no account area to visit afterwards and no second step: proving the
// key is the registration.
class PortalApi {
public:
    PortalApi(PortalApiOptions options, GrantStore& grants);
    ~PortalApi();

    PortalApi(const PortalApi&) = delete;
    PortalApi& operator=(const PortalApi&) = delete;

    // Binds and starts serving (port 0 lets the kernel pick). Returns the bound
    // port, 0 when the socket could not be taken.
    int bind(const std::string& host, int port);
    // Parks the caller until stop(). The engine serves on its own threads.
    void wait();
    void stop();

private:
    // The reseed archive as this portal last had it from the messaging server,
    // and when. Held briefly: the archive itself is repacked no more than hourly,
    // so asking more often would only move bytes.
    std::string reseedArchive();
    std::mutex reseedMutex_;
    std::string reseedSu3_;
    std::int64_t reseedFetchedAt_ = 0;

    void setupRoutes();
    // Registers the browser-facing routes (the page and its files).
    void setupWebRoutes();
    // The portal's one page, in whatever state the visitor is in. `error` is
    // shown on the step the visitor is standing on, empty when there is none.
    std::string homePage(const bazarish::http::Request& request, const std::string& user,
        const std::string& error);
    // The language this request is answered in, and the switch that changes it.
    std::string language(const bazarish::http::Request& request) const;
    std::string languageSwitch(const std::string& lang, const std::string& here) const;
    // The page shell around one of the content templates.
    std::string page(const bazarish::http::Request& request, const std::string& title,
        const std::string& session,
        const std::string& content);
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
    Messages messages_;
    GrantStore& grants_;
    LoginChallenge login_;
    PortalSession session_;
    std::unique_ptr<bazarish::http::Server> http_;
    bazarish::StopGate stopGate_;
};

}  // namespace bazarish::service
