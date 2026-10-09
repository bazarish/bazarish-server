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
    std::string serverFingerprint;
    std::string challengeSecret;
    std::string sessionSecret;
    std::int64_t sessionTtlSeconds = 3600;
    std::function<std::string()> fetchReseedArchive;
    std::filesystem::path assetsDirectory;
    std::shared_ptr<NodeSettings> settings;

    std::function<std::optional<MailboxUsage>(const std::string& user)> accountUsage;

    std::function<void(const std::string& user)> deleteAccount;
};

class PortalApi {
public:
    PortalApi(PortalApiOptions options, GrantStore& grants);
    ~PortalApi();

    PortalApi(const PortalApi&) = delete;
    PortalApi& operator=(const PortalApi&) = delete;

    int bind(const std::string& host, int port);
    void wait();
    void stop();

private:
    std::string reseedArchive();
    std::mutex reseedMutex_;
    std::string reseedSu3_;
    std::int64_t reseedFetchedAt_ = 0;

    void setupRoutes();
    void setupWebRoutes();
    std::string homePage(const bazarish::http::Request& request, const std::string& user,
        const std::string& error);
    std::string language(const bazarish::http::Request& request) const;
    std::string languageSwitch(const std::string& lang, const std::string& here) const;
    std::string page(const bazarish::http::Request& request, const std::string& title,
        const std::string& session,
        const std::string& content);
    std::map<std::string, std::string> accountValues(const std::string& user,
        const std::optional<GrantStore::SubscriptionGrant>& subscription);

    NodeSettings::Values settings() const { return settings_->get(); }

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
