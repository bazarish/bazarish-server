// Bazarish project (c) 2026
#pragma once

#include "GrantStore.hpp"
#include "NodeSettings.hpp"
#include "OperatorPush.hpp"
#include "SubscriptionStore.hpp"

#include <nlohmann/json.hpp>

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>
#include <Restart.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::http {
class Server;
}

namespace bazarish::service {

struct AccountApiOptions {
    std::string serverFingerprint;
    // The server card the node hands its own clients (DER).
    Bytes serverCardDer;
    std::string version;
    std::vector<std::string> operatorFingerprints;
    std::function<void()> requestRestart;

    std::function<std::optional<ServedDestination>(const std::string& user,
        const std::string& transientB64, std::int64_t expiresUnix)>
        publishI2pTransient;

    std::function<bool(const std::string& user)> forgetMailbox;

    std::function<void(const std::string& user, std::uint64_t quotaBytes)> publishQuota;


    std::shared_ptr<NodeSettings> settings;
    std::string tlsCertificate;
    std::string tlsKey;
    std::vector<std::string> opsClientPins;
};

class AccountApi {
public:
    AccountApi(SubscriptionStore& store, GrantStore& grants, AccountApiOptions options);
    ~AccountApi();

    AccountApi(const AccountApi&) = delete;
    AccountApi& operator=(const AccountApi&) = delete;

    int bind(const std::string& host, int port);
    int bindOps(const std::string& host, int port);
    void wait();
    void stop();

private:
    void revokeDestination(const std::string& user);
    void deleteAccount(const std::string& user);

    std::string destinationOf(const std::optional<SubscriptionStore::Account>& held);

    NodeSettings::Values settings() const { return settings_->get(); }

    nlohmann::json userRecord(
        const std::string& user, const std::optional<GrantStore::Approval>& approval);

    void setupRoutes();
    void setupOpsRoutes();

    std::shared_ptr<NodeSettings> settings_;
    SubscriptionStore& store_;
    GrantStore& grants_;
    const AccountApiOptions options_;
    std::unique_ptr<bazarish::http::Server> http_;
    std::unique_ptr<bazarish::http::Server> ops_;
    std::int64_t startedAt_ = 0;
    bazarish::StopGate stopGate_;

    auth::ReplayCache replayCache_;
};

}  // namespace bazarish::service
