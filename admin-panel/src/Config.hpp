// Bazarish project (c) 2026
#pragma once

#include <string>
#include <vector>

namespace bazarish::admin {

// One managed service the panel monitors and acts on. The panel authenticates to
// each service by signing its requests with the panel identity; the service must
// be started with that identity's fingerprint as an --operator-fingerprint. No
// shared secret travels in the config.
struct ServiceEntry {
    std::string name;
    std::string kind;  // server-core | service-node | facade | alias-resolver
    std::string url;   // e.g. http://127.0.0.1:8420
};

// The panel configuration, loaded from a JSON file at startup. The admin pastes
// their own Bazarish fingerprint (from `bazarish-client whoami`) into `admin`;
// only that identity may sign in.
struct Config {
    std::string admin;
    std::string audience = "bazarish-admin-panel";
    std::string listenHost = "127.0.0.1";
    int listenPort = 8460;
    std::vector<ServiceEntry> services;

    // Parses configuration from JSON text. Throws std::runtime_error on malformed
    // input or a missing required field (the admin fingerprint).
    static Config fromJson(const std::string& text);

    // Reads and parses the configuration file. Throws if it cannot be read.
    static Config fromFile(const std::string& path);
};

}  // namespace bazarish::admin
