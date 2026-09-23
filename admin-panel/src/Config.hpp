// Bazarish project (c) 2026
#pragma once

#include <bazarish/Portal.hpp>

#include <string>
#include <vector>

namespace bazarish::admin {

// One managed service the panel monitors and acts on. The panel authenticates to
// each service by signing its requests with the panel identity; the service must
// be started with that identity's fingerprint as an --operator-fingerprint. No
// shared secret travels in the config.
struct ServiceEntry {
    std::string name;
    std::string kind;  // server-core | service-node | facade | gateway
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

    friend bool operator==(const Fleet&, const Fleet&) = default;
};

// Whether the panel knows how to talk to a service of this kind. One list, used
// both when the config file is read and when the panel is edited from the panel.
bool isKnownServiceKind(const std::string& kind);

struct Config {
    // Who may sign in. Empty means nobody has claimed this panel yet, which is
    // the one state where the setup wizard answers: a fresh install has no
    // administrator until the first key signs in and becomes one.
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
