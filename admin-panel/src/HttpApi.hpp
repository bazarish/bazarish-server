// Bazarish project (c) 2026
#pragma once

#include "AdminAuth.hpp"
#include "Config.hpp"
#include "SessionStore.hpp"

#include <bazarish/WebAssets.hpp>

#include <condition_variable>
#include <filesystem>
#include <cstdint>
#include <memory>
#include <mutex>
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
    HttpApi(Config config, const Identity& identity, HttpApiOptions options);
    ~HttpApi();

    HttpApi(const HttpApi&) = delete;
    HttpApi& operator=(const HttpApi&) = delete;

    bool listen(const std::string& host, int port);
    int bindToAnyPort(const std::string& host);
    bool listenAfterBind();
    bool isRunning() const;
    void stop();

private:
    // Binds on a chosen port (0 lets the kernel pick) and starts serving.
    int bindToAnyPort(const std::string& host, int port);
    void registerRoutes();
    // The configured service of a kind ("service-node", "server-core", ...), or
    // null when the fleet this panel was given has none.
    const ServiceEntry* serviceOfKind(const std::string& kind) const;
    // Signs a call to the service node and answers with its reply verbatim.
    void proxyToNode(bazarish::http::Response& response, const std::string& method,
        const std::string& path, const std::string& body);

    Config config_;
    const Identity& identity_;
    HttpApiOptions options_;
    AdminAuth auth_;
    SessionStore sessions_;
    WebAssets assets_;
    std::unique_ptr<bazarish::http::Server> http_;
    bool running_ = false;

    // listenAfterBind() parks the caller's thread here until stop() releases it.
    std::mutex stopMutex_;
    std::condition_variable stopCv_;
    bool stopping_ = false;
};

}  // namespace bazarish::admin
