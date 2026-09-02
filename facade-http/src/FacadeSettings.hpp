// Bazarish project (c) 2026
#pragma once

#include <filesystem>
#include <mutex>
#include <string>

namespace bazarish::facade {

// A base path must be a single absolute URI prefix the facade can strip: leading
// slash, no trailing slash, no query or fragment.
bool isValidBasePath(const std::string& path);

// The facade's configuration while it runs, and the writer that puts it back in
// the file it was read from.
//
// The facade holds no keys and stores nothing, so everything here is about where
// it stands: the secret prefix the whole clearnet API lives under, the two
// backends it forwards to, the sockets it binds, and its I2P side. Only the log
// level applies at once - the rest is read when it starts.
class FacadeSettings {
public:
    struct Values {
        std::string logLevel;
        // The secret prefix the clearnet API is served under. Changing it is a
        // change to every client's facade URL: the server descriptor carries the
        // prefix, so a new one has to reach the clients before they lose the old
        // one.
        std::string basePath;
        // Where it forwards: the messaging server and the service node.
        std::string messagingHost;
        int messagingPort = 0;
        std::string accountHost;
        int accountPort = 0;
        // The public socket, and the operator-only one that answers /healthz.
        std::string listenHost;
        int listenPort = 0;
        std::string opsHost;
        int opsPort = 0;
        // The I2P side: whether the facade publishes destinations of its own, how
        // many, how private their tunnels are and how many tunnels each carries.
        bool i2pEnabled = false;
        int i2pDestinations = 0;
        std::string i2pPrivacy;
        int i2pTunnelQuantity = 0;
    };

    FacadeSettings(std::filesystem::path configPath, Values initial);

    Values get() const;

    // Applies the values and writes them to the config file. Throws when the
    // file cannot be written.
    void set(const Values& values);

private:
    void persist(const Values& values) const;

    std::filesystem::path configPath_;
    mutable std::mutex mutex_;
    Values values_;
};

}  // namespace bazarish::facade
