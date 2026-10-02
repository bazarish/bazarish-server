// Bazarish project (c) 2026
#pragma once

#include "AdminAuth.hpp"
#include "Config.hpp"
#include "PanelSettings.hpp"
#include "SessionStore.hpp"

#include <bazarish/Restart.hpp>
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
    // Asked for from the Panel tab when a setting only a start reads has been
    // written - the panel's own listener. Empty answers that this panel cannot
    // restart itself.
    std::function<void()> requestRestart;
    std::int64_t sessionTtlSeconds = 3600;
    // Where the panel's web files live (page shell, stylesheet, script, logo).
    std::filesystem::path assetsDirectory;
};

// The admin panel web surface. Login is sign-in-with-key verified locally against
// the configured admin identities (no backend needed). Past the sign-in page the
// panel is a script talking to a small JSON API here: it probes each configured
// service's /healthz and passes the account calls through to the service node,
// which owns the accounts and does the searching.
class HttpApi {
public:
    // identity is the panel's own signing identity (it signs every service call);
    // it must outlive the HttpApi.
    HttpApi(std::shared_ptr<PanelSettings> settings, const Identity& identity,
        HttpApiOptions options);
    ~HttpApi();

    HttpApi(const HttpApi&) = delete;
    HttpApi& operator=(const HttpApi&) = delete;

    // Binds and starts serving (port 0 lets the kernel pick). Returns the bound
    // port, 0 when the socket could not be taken.
    int bind(const std::string& host, int port);
    // Parks the caller until stop(). The engine serves on its own threads.
    void wait();
    void stop();

private:
    void registerRoutes();
    // The service of a kind inside one fleet, or null when that fleet has none.
    // A fleet named by nothing is the first one, which is what a single
    // deployment always has.
    std::optional<ServiceEntry> serviceOfKind(
        const std::string& fleet, const std::string& kind) const;
    // Signs a call to a fleet's service node and answers with its reply verbatim.
    void proxyToNode(const std::string& fleet, bazarish::http::Response& response,
        const std::string& method, const std::string& path, const std::string& body);

    std::shared_ptr<PanelSettings> settings_;
    const Identity& identity_;
    HttpApiOptions options_;
    AdminAuth auth_;
    SessionStore sessions_;
    WebAssets assets_;
    std::unique_ptr<bazarish::http::Server> http_;
    bazarish::StopGate stopGate_;
};

}  // namespace bazarish::admin
