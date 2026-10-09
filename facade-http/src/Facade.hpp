// Bazarish project (c) 2026
#pragma once

#include "FacadeSettings.hpp"
#include "Load.hpp"

#include <bazarish/HttpServer.hpp>
#include <Restart.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace bazarish::facade {

struct FacadeOptions {
    std::string messagingHost = "127.0.0.1";
    int messagingPort = 8420;
    std::string messagingPin;
    std::string basePath;
    std::shared_ptr<FacadeSettings> settings;
    std::function<void()> requestRestart;
    std::string stateDirectory;
    std::string version;
    std::vector<std::string> operatorFingerprints;

    // The certificate this facade presents on both sockets, and the key allowed
    // to open the operator's one: the admin panel.
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

    void wait();
    void stop();

private:
    void setupRoutes();
    void setupOpsRoutes();

    const FacadeOptions options_;
    std::unique_ptr<bazarish::http::Server> http_;
    std::unique_ptr<bazarish::http::Server> ops_;
    Load load_;
    bazarish::StopGate stopGate_;
    std::int64_t startedAt_ = 0;
};

}  // namespace bazarish::facade
