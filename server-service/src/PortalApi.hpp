// Bazarish project (c) 2026
#pragma once

#include "GrantStore.hpp"
#include "LoginMailbox.hpp"
#include "Messages.hpp"
#include "NodeSettings.hpp"
#include "OperatorPush.hpp"

#include <bazarish/LoginChallenge.hpp>
#include <bazarish/PortalSession.hpp>
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
    std::function<std::string()> fetchReseedArchive;
    std::filesystem::path assetsDirectory;
    std::shared_ptr<NodeSettings> settings;
    std::shared_ptr<LoginMailbox> logins;

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
    void stop();

private:
    std::string reseedArchive();
    std::mutex reseedMutex_;
    std::string reseedSu3_;
    std::int64_t reseedFetchedAt_ = 0;
    bool reseedFetching_ = false;

    void setupWebRoutes();
    std::string homePage(const bazarish::http::Request& request, const std::string& user,
        const std::string& error, bazarish::http::Response& response);
    std::string signInPanel(const std::string& error, bazarish::http::Response& response);
    std::string language(const bazarish::http::Request& request) const;
    std::string languageSwitch(const std::string& lang, const std::string& here) const;
    std::string page(const bazarish::http::Request& request, const std::string& title,
        const std::string& session,
        const std::string& content);
    std::map<std::string, std::string> accountValues(const std::string& user);

    NodeSettings::Values settings() const { return settings_->get(); }

    PortalApiOptions options_;
    std::shared_ptr<NodeSettings> settings_;
    WebAssets assets_;
    Messages messages_;
    GrantStore& grants_;
    LoginChallenge login_;
    PortalSession session_;
    std::unique_ptr<bazarish::http::Server> http_;
};

}  // namespace bazarish::service
