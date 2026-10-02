// Bazarish project (c) 2026
#pragma once

#include <bazarish/Portal.hpp>

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace bazarish::admin {

// The kinds of service a panel knows how to talk to. The alias service is not
// among them: it is one central service for the whole project, not part of an
// operator's server.
inline constexpr const char* kServerCoreKind = "server-core";
inline constexpr const char* kServiceNodeKind = "service-node";
inline constexpr const char* kFacadeKind = "facade";
inline constexpr const char* kGatewayKind = "gateway";

// One managed service the panel monitors and acts on. The panel authenticates to
// each service by signing its requests with the panel identity, so that
// identity's fingerprint has to be in the service's own "operators" list. No
// shared secret travels in the config.
struct ServiceEntry {
    std::string name;
    std::string kind;  // one of the kinds above
    std::string url;   // e.g. http://127.0.0.1:8420
    // A gateway answers at a secret path and only to requests carrying its
    // token. The path is part of the URL; the token is here, or comes in the
    // URL's fragment, which is how a gateway's address is handed out.
    std::string token;

    friend bool operator==(const ServiceEntry&, const ServiceEntry&) = default;
};

// Moves a "#token" fragment out of the URL and into the token field, so one
// pasted address and a separately named host and token end up the same shape.
void takeTokenFromUrl(ServiceEntry& entry);

// One deployment the panel manages: a messaging server, the service node bound to
// it, and the facades that front the pair. That is the unit that scales - a node
// is bound to one messaging server's card - so the panel groups by it.
struct Fleet {
    std::string name;
    std::vector<ServiceEntry> services;

    friend bool operator==(const Fleet&, const Fleet&) = default;
};

// Whether the panel knows how to talk to a service of this kind. One list, used
// both when the config file is read and when the panel is edited from the panel.
bool isKnownServiceKind(const std::string& kind);

// The deployments as both the config file and the panel's own API spell them.
nlohmann::json fleetsJson(const std::vector<Fleet>& fleets);

// The panel configuration, as the file holds it.
struct Config {
    // Who may sign in, by fingerprint - the one a client shows in its signature
    // window. Empty means nobody has claimed this panel yet, which is the one
    // state where the setup wizard answers: a fresh install has no administrator
    // until the first key signs in and becomes one.
    std::vector<std::string> admins;
    // Where the panel keeps its own signing identity, and where its web files
    // live. In the config like everything else: a flag that could override them
    // would be a second answer to the same question.
    std::string stateDir;
    std::string assetsDir;
    // Who the panel says it is when it asks an operator to sign a login. The
    // client shows these words before signing, so they have to be the ones the
    // operator has in front of them: by default where the panel listens, and
    // something else only when it is fronted by a name of its own.
    service::LoginConsumer consumer;
    std::string listenHost = "127.0.0.1";
    int listenPort = 8460;
    // The deployments this panel manages. A config that lists services without
    // naming a fleet is read as one unnamed fleet, which is the common case.
    std::vector<Fleet> fleets;

    // Parses configuration from JSON text. Throws std::runtime_error on malformed
    // input. An absent or empty "admin" is not an error - it is an unclaimed
    // panel, which the setup wizard exists for.
    static Config fromJson(const std::string& text);

    // Reads and parses the configuration file. Throws if it cannot be read.
    static Config fromFile(const std::string& path);
};

}  // namespace bazarish::admin
