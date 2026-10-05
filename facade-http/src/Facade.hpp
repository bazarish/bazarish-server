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
    // Secret URI prefix the facade requires and strips before forwarding
    // (e.g. "/h9fd/kshdcy/secretdkg"). The whole clearnet API lives under it, and
    // it travels solely inside the facade URL of a server descriptor. Empty only
    // when the operator opted out (a fronting proxy owns the secret then).
    std::string basePath;
    // The settings an operator turns from the panel, and the file they go back
    // to. Null leaves the settings routes out.
    std::shared_ptr<FacadeSettings> settings;
    // Asked for by the panel once a setting that only a start reads has been
    // written. Empty answers that this facade cannot restart itself.
    std::function<void()> requestRestart;
    // Where its state lives, for the operator to read.
    std::string stateDirectory;
    // Version string reported by /healthz.
    std::string version;
    // Fingerprints authorised to call the ops listener (the admin panel). The
    // caller proves possession by signing the request; no shared secret. Empty
    // refuses every caller.
    std::vector<std::string> operatorFingerprints;
};

// The HTTP facade: the "last mile" between client and infrastructure. It forwards
// two requests to the messaging server - the sealed client tunnel and the public
// server card - and answers everything else with the same bare 404. It holds no
// keys, parses no content, stores nothing and logs nothing identifying.
//
// Two sockets, and nothing crosses between them: the public one answers only
// under the secret base path (anything else, /healthz included, is a plain 404,
// so a probe of the bare host learns nothing), while the ops one serves the
// operator-signed health, settings and restart and is never published to clients.
class Facade {
public:
    explicit Facade(FacadeOptions options);
    ~Facade();

    Facade(const Facade&) = delete;
    Facade& operator=(const Facade&) = delete;

    // Binds and starts serving (port 0 lets the kernel pick). Returns the bound
    // port, 0 when the socket could not be taken.
    int bind(const std::string& host, int port);
    int bindOps(const std::string& host, int port);

    // Parks the caller until stop(); both listeners end together.
    void wait();
    void stop();

private:
    void setupRoutes();
    void setupOpsRoutes();

    const FacadeOptions options_;
    std::unique_ptr<bazarish::http::Server> http_;
    std::unique_ptr<bazarish::http::Server> ops_;
    // What is passing through right now, for the operator panel.
    Load load_;
    bazarish::StopGate stopGate_;
    std::int64_t startedAt_ = 0;
};

}  // namespace bazarish::facade
