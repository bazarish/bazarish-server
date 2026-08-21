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
    std::string kind;  // server-core | service-node | facade
    std::string url;   // e.g. http://127.0.0.1:8420
};

// The panel configuration, loaded from a JSON file at startup. An admin pastes
// their own Bazarish fingerprint (from `bazarish-client whoami`) into `admin`,
// which is one fingerprint or a list of them; only those identities may sign in.
// One deployment the panel manages: a messaging server, the service node bound
// to it, and the facades that front the pair. That is the unit that scales - a
// subscription certificate names one messaging server, and the node that issues
// it is bound to that server's card - so the panel groups by it.
struct Fleet {
    std::string name;
    std::vector<ServiceEntry> services;
};

struct Config {
    std::vector<std::string> admins;
    // Where the panel keeps its own signing identity, and where its web files
    // live. In the config like everything else: a flag that could override them
    // would be a second answer to the same question.
    std::string stateDir;
    std::string assetsDir;
    std::string audience = "bazarish-admin-panel";
    std::string listenHost = "127.0.0.1";
    int listenPort = 8460;
    // The deployments this panel manages. A config that lists services without
    // naming a fleet is read as one unnamed fleet, which is the common case.
    std::vector<Fleet> fleets;

    // Parses configuration from JSON text. Throws std::runtime_error on malformed
    // input or a missing required field (the admin fingerprints).
    static Config fromJson(const std::string& text);

    // Reads and parses the configuration file. Throws if it cannot be read.
    static Config fromFile(const std::string& path);
};

}  // namespace bazarish::admin
