// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <memory>
#include <string>

namespace httplib {
class Server;
}

namespace bazarish::facade {

struct FacadeOptions {
    std::string messagingHost = "127.0.0.1";
    int messagingPort = 8420;
    std::string accountHost = "127.0.0.1";
    int accountPort = 8421;
    // Secret URI prefix the facade requires and strips before forwarding
    // (e.g. "/s/9f3c..."). Empty means the reverse proxy owns the secret.
    std::string basePath;
};

// The HTTP facade: the "last mile" between client and infrastructure. A
// transparent reverse proxy that routes by path prefix to the messaging
// server (/v1/messaging/*) or the service node (/v1/account/*). Holds no
// keys, parses no content, stores nothing, logs nothing identifying.
class Facade {
public:
    explicit Facade(FacadeOptions options);
    ~Facade();

    bool listen(const std::string& host, int port);
    int bindToAnyPort(const std::string& host);
    bool listenAfterBind();
    void stop();

private:
    void setupRoutes();

    const FacadeOptions options_;
    std::unique_ptr<httplib::Server> http_;
};

}  // namespace bazarish::facade
