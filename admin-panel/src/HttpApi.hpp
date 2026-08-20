// Bazarish project (c) 2026
#pragma once

#include "AdminAuth.hpp"
#include "Config.hpp"
#include "SessionStore.hpp"

#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

namespace bazarish::http {
class Server;
}

namespace bazarish {
class Identity;
}

namespace bazarish::admin {

struct HttpApiOptions {
    std::string version;
    std::int64_t sessionTtlSeconds = 3600;
};

// The admin panel web surface. Login is sign-in-with-key verified locally against
// the configured admin identity (no backend needed); the dashboard probes each
// configured service's /healthz and exposes the operator actions those services
// already provide.
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

    Config config_;
    const Identity& identity_;
    HttpApiOptions options_;
    AdminAuth auth_;
    SessionStore sessions_;
    std::unique_ptr<bazarish::http::Server> http_;
    bool running_ = false;

    // listenAfterBind() parks the caller's thread here until stop() releases it.
    std::mutex stopMutex_;
    std::condition_variable stopCv_;
    bool stopping_ = false;
};

}  // namespace bazarish::admin
