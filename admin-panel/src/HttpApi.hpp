// Bazarish project (c) 2026
#pragma once

#include "AdminAuth.hpp"
#include "Config.hpp"
#include "PanelSettings.hpp"

#include <bazarish/Tls.hpp>
#include "SessionStore.hpp"

#include <Restart.hpp>
#include <bazarish/WebAssets.hpp>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace bazarish::http {
class Server;
struct Response;
}

namespace bazarish {
class Identity;
}

namespace bazarish::admin {

struct HttpApiOptions {
    std::string version;
    std::function<void()> requestRestart;
    std::int64_t sessionTtlSeconds = 3600;
    std::filesystem::path assetsDirectory;
};

class HttpApi {
public:
    HttpApi(std::shared_ptr<PanelSettings> settings, const Identity& identity,
        bazarish::tls::Credential credential,
        HttpApiOptions options);
    ~HttpApi();

    HttpApi(const HttpApi&) = delete;
    HttpApi& operator=(const HttpApi&) = delete;

    int bind(const std::string& host, int port);
    void wait();
    void stop();

private:
    void registerRoutes();
    std::optional<ServiceEntry> serviceOfKind(
        const std::string& fleet, const std::string& kind) const;
    void proxyToNode(const std::string& fleet, bazarish::http::Response& response,
        const std::string& method, const std::string& path, const std::string& body);

    std::shared_ptr<PanelSettings> settings_;
    const Identity& identity_;
    bazarish::tls::Credential credential_;
    HttpApiOptions options_;
    AdminAuth auth_;
    SessionStore sessions_;
    WebAssets assets_;
    std::unique_ptr<bazarish::http::Server> http_;
    bazarish::StopGate stopGate_;
};

}  // namespace bazarish::admin
