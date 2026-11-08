// Bazarish project (c) 2026
#pragma once

#include "FacadeSettings.hpp"

#include <FleetPorts.hpp>
#include <Restart.hpp>
#include "Load.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/HttpServer.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace bazarish::facade {

inline constexpr const char* kDefaultUpstreamHost = fleet::kLoopback;
inline constexpr int kDefaultMessagingPort = fleet::kCorePort;
inline constexpr int kDefaultServiceNodePort = fleet::kNodePort;

struct Upstream {
    std::string host;
    int port = 0;
    std::string pin;
};

struct FacadeOptions {
    Upstream messaging{kDefaultUpstreamHost, kDefaultMessagingPort, {}};
    Upstream serviceNode{kDefaultUpstreamHost, kDefaultServiceNodePort, {}};
    std::string address;
    std::shared_ptr<FacadeSettings> settings;
    std::function<void()> requestRestart;
    std::string stateDirectory;
    std::string version;
    std::vector<std::string> operatorFingerprints;
    std::string tlsCertificate;
    std::string tlsKey;
    std::vector<std::string> opsClientPins;
};

class Facade {
public:
    explicit Facade(FacadeOptions options);
    ~Facade();

    Facade(const Facade&) = delete;
    Facade& operator=(const Facade&) = delete;

    int bind(const std::string& host, int port);
    int bindOps(const std::string& host, int port);
    int bindDirect(const std::string& host, int port);

    void wait();
    void stop();

private:
    void setupRoutes(bazarish::http::Server& server);
    void setupOpsRoutes();

    const FacadeOptions options_;
    // Before the servers: their requests still in flight hold these until the servers are gone.
    Load load_;
    bazarish::auth::ReplayCache operatorReplays_;
    bazarish::StopGate stopGate_;
    std::int64_t startedAt_ = 0;
    std::unique_ptr<bazarish::http::Server> http_;
    std::unique_ptr<bazarish::http::Server> ops_;
    std::unique_ptr<bazarish::http::Server> direct_;
};

}  // namespace bazarish::facade
