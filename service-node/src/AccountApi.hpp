// Bazarish project (c) 2026
#pragma once

#include "UserLocks.hpp"
#include "LoginMailbox.hpp"
#include "GrantStore.hpp"
#include "NodeSettings.hpp"
#include "OperatorPush.hpp"
#include "SubscriptionStore.hpp"

#include <nlohmann/json.hpp>

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>
#include <Restart.hpp>
#include <TunnelFace.hpp>

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
    Bytes serverCardDer;
    std::shared_ptr<Key> sealingKey;
    Bytes nodeCardDer;
    std::string version;
    std::vector<std::string> operatorFingerprints;
    std::function<void()> requestRestart;

    std::function<std::optional<ServedDestination>(const std::string& user,
        const std::string& transientB64, std::int64_t expiresUnix, const AddressKeys& keys)>
        publishI2pTransient;

    std::function<bool(const std::string& user)> forgetMailbox;

    std::function<void(const std::string& user, std::uint64_t quotaBytes)> publishQuota;
    // A private node, such as a bot's own: a signer outside this set is refused. Empty: a public node.
    std::function<bool(const std::string& user)> admitsUser;
    std::shared_ptr<UserLocks> userLocks = std::make_shared<UserLocks>();


    std::shared_ptr<NodeSettings> settings;
    std::shared_ptr<LoginMailbox> logins;
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

    NodeSettings::Values settings() const { return settings_->get(); }

    nlohmann::json userRecord(
        const std::string& user, const std::optional<GrantStore::Approval>& approval);

    void setupRoutes();
    void setupOpsRoutes();

    std::shared_ptr<NodeSettings> settings_;
    SubscriptionStore& store_;
    GrantStore& grants_;
    const AccountApiOptions options_;
    std::int64_t startedAt_ = 0;
    bazarish::StopGate stopGate_;
    auth::ReplayCache replayCache_;
    server::TunnelFace tunnel_;
    // Last: the servers go first, while what their handlers touch is still here.
    std::unique_ptr<bazarish::http::Server> http_;
    std::unique_ptr<bazarish::http::Server> ops_;
};

}  // namespace bazarish::service
