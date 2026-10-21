// Bazarish project (c) 2026
#pragma once

#include "ServerSettings.hpp"
#include "Storage.hpp"

#include "SessionStore.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/HttpServer.hpp>
#include <Restart.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace bazarish::server {

class EventGate;

struct DestinationAssignment {
    std::string dest;
    std::shared_ptr<Key> servingKey;
    std::string state;
};

using AssignDestinationFn = std::function<DestinationAssignment(const std::string& user)>;

struct HttpApiOptions {
    std::shared_ptr<ServerSettings> settings;
    std::function<void()> requestRestart;
    std::string stateDirectory;
    std::string fingerprint;
    std::uint64_t defaultQuotaBytes = 50 * 1024 * 1024;
    std::vector<std::string> operatorFingerprints;
    std::string version;
    std::function<DestinationAssignment(const std::string& user,
        const std::string& transientB64, std::int64_t expiresUnix)>
        provisionI2pDest;
    std::function<void(const std::string& user)> takeI2pDestOffline;
    std::function<void(const std::string& user)> forgetI2pDest;
    AssignDestinationFn assignDestination;

    std::function<std::vector<Bytes>(std::size_t count)> reseedSample;
    std::function<std::uint64_t()> diskUsage;
    int maxEventWaitSeconds = 30;
    EventGate* eventGate = nullptr;
    std::shared_ptr<const Identity> identity;
    std::shared_ptr<Key> sealingKey;
    Bytes serverCardDer;
    std::string serviceNodeUrl;
    std::string serviceNodePin;
    std::string tlsCertificate;
    std::string tlsKey;
    std::vector<std::string> opsClientPins;
    std::function<void(const std::vector<std::string>& gateways)> gatewaysChanged;
};

class HttpApi {
public:
    HttpApi(Storage& storage, HttpApiOptions options);
    ~HttpApi();

    HttpApi(const HttpApi&) = delete;
    HttpApi& operator=(const HttpApi&) = delete;

    int bind(const std::string& host, int port);
    int bindOps(const std::string& host, int port);
    void wait();
    void stop();

private:
    void wakeUser(const std::string& user);

    void setupRoutes();
    void setupOpsRoutes();
    std::optional<bazarish::http::Response> authenticateRequest(
        const bazarish::http::Request& request, std::string* outUser,
        bool allowSession = true);
    void serveTunnel(const bazarish::http::Request& request, bazarish::http::Responder respond);
    bazarish::http::Response forwardToNode(
        const bazarish::http::Request& request, const std::string& user);
    std::string reseedArchive();

    void expiredSweepLoop();

    std::mutex reseedMutex_;
    std::string reseedSu3_;
    std::int64_t reseedPackedAt_ = 0;

    Storage& storage_;
    const HttpApiOptions options_;

    std::unique_ptr<bazarish::http::Server> http_;
    std::unique_ptr<bazarish::http::Server> ops_;
    SessionStore sessions_;
    std::int64_t startedAt_ = 0;

    bazarish::StopGate stopGate_;
    std::thread janitorThread_;

    auth::ReplayCache replayCache_;
};

}  // namespace bazarish::server
