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
    // The blob store's local web backend; only the upload endpoint is forwarded
    // (downloads/confirms are I2P-only and never clearnet-reachable).
    std::string blobStorageHost = "127.0.0.1";
    int blobStoragePort = 8456;
    // Secret URI prefix the facade requires and strips before forwarding
    // (e.g. "/s/9f3c..."). Empty means the reverse proxy owns the secret.
    std::string basePath;
    // Version string reported by /healthz.
    std::string version;
    // Fingerprints authorised to call /healthz (the admin panel). The caller
    // proves possession by signing the request; no shared secret. Empty disables
    // /healthz.
    std::vector<std::string> operatorFingerprints;
};

// The HTTP facade: the "last mile" between client and infrastructure. A
// transparent reverse proxy that routes by path prefix to the messaging
// server (/v1/messaging/*), the service node (/v1/account/*) or the blob store
// upload endpoint (/v1/storage/blob). Holds no keys, parses no content, stores
// nothing, logs nothing identifying.
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
    std::int64_t startedAt_ = 0;
};

}  // namespace bazarish::facade
