// Bazarish project (c) 2026
#pragma once

#include <bazarish/GatewayProtocol.hpp>

#include <bazarish/ConfigFile.hpp>

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace bazarish::gateway {

// Everything the daemon runs on. The secret path and the token are mandatory
// and have no defaults: a gateway that came up without them would be a gateway
// anybody could walk into, and a default nobody changed is the same thing.
struct Settings {
    std::string listenHost = "127.0.0.1";
    int listenPort = 0;
    std::string basePath;
    std::string token;
    std::filesystem::path stateDir;
    // Where a router with no peers gets its first netDb. Empty leaves the
    // engine its built-in hosts.
    std::vector<std::string> reseedUrls;
    // The answer to a decoy is drawn between these. Both are the operator's to
    // set, because only the operator knows what traffic to this host looks like.
    std::size_t decoyMinBytes = kDecoyMinBytes;
    std::size_t decoyMaxBytes = kDecoyMaxBytes;
    // The one answer every request that is not for the gateway receives. It is
    // one template so that the wrong path, the right path with no token and the
    // right path with the wrong token are indistinguishable.
    std::string notFoundBody;
    std::string serverName = "nginx";
    // How long a session outlives its last socket. The client drops its own on
    // purpose, so this is the other half of the trade its gap setting makes:
    // long enough for a lift or a handover, short enough that an abandoned
    // phone does not cost tunnels for ever.
    std::int64_t sessionTtlSeconds = kSessionTtl.count();

    // Throws when something mandatory is missing or makes no sense.
    static Settings from(const ConfigView& config);
};

}  // namespace bazarish::gateway
