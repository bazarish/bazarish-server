// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

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
    // (e.g. "/h9fd/kshdcy/secretdkg"). The whole clearnet API lives under it -
    // including the unauthenticated reseed, whose only gate this is - and it
    // travels solely inside the facade URL of a server descriptor. Empty only
    // when the operator opted out (a fronting proxy owns the secret then).
    std::string basePath;
    // Version string reported by /healthz.
    std::string version;
    // Fingerprints authorised to call /healthz on the ops listener (the admin
    // panel). The caller proves possession by signing the request; no shared
    // secret. Empty refuses every caller.
    std::vector<std::string> operatorFingerprints;
};

// The HTTP facade: the "last mile" between client and infrastructure. A
// transparent reverse proxy that routes by path prefix to the messaging
// server (/v1/messaging/*), the service node (/v1/account/*). Holds no keys, parses no content, stores
// nothing, logs nothing identifying.
//
// Two sockets, and nothing crosses between them: the public one answers only
// under the secret base path (anything else, /healthz included, is a plain 404,
// so a probe of the bare host learns nothing), while the ops one serves only the
// operator-signed /healthz and is never published to clients.
class Facade {
public:
    explicit Facade(FacadeOptions options);
    ~Facade();

    bool listen(const std::string& host, int port);
    int bindToAnyPort(const std::string& host);
    bool listenAfterBind();

    bool bindOps(const std::string& host, int port);
    int bindOpsToAnyPort(const std::string& host);
    bool listenOpsAfterBind();

    void stop();

private:
    void setupRoutes();
    void setupOpsRoutes();

    const FacadeOptions options_;
    std::unique_ptr<httplib::Server> http_;
    std::unique_ptr<httplib::Server> ops_;
    std::int64_t startedAt_ = 0;
};

}  // namespace bazarish::facade
