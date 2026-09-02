// Bazarish project (c) 2026
#include "Config.hpp"

#include <nlohmann/json.hpp>

#include <fstream>
#include <stdexcept>

namespace bazarish::admin {

namespace {

// What a deployment is made of. The alias service is not here: it is one central
// service for the whole project, not part of anyone's server, and an operator of
// a server has nothing to do with it.
const char* const kKnownKinds[] = {"server-core", "service-node", "facade"};

}  // namespace

bool isKnownServiceKind(const std::string& kind)
{
    for (const char* const known : kKnownKinds) {
        if (kind == known) {
            return true;
        }
    }
    return false;
}

Config Config::fromJson(const std::string& text)
{
    const nlohmann::json json = nlohmann::json::parse(text, nullptr, true, true);

    Config config;
    // No "admin" at all is how a fresh install arrives: the panel comes up
    // unclaimed and the setup wizard hands it to the first key that signs in.
    if (json.contains("admin")) {
        const nlohmann::json& admin = json.at("admin");
        if (admin.is_array()) {
            config.admins = admin.get<std::vector<std::string>>();
        } else if (!admin.is_null()) {
            config.admins = {admin.get<std::string>()};
        }
    }
    for (const std::string& fingerprint : config.admins) {
        if (fingerprint.empty()) {
            throw std::runtime_error("config: \"admin\" fingerprint must not be empty");
        }
    }
    config.stateDir = json.value("state", std::string());
    config.assetsDir = json.value("assets", std::string());
    if (json.contains("listen")) {
        const nlohmann::json& listen = json.at("listen");
        if (listen.contains("host")) {
            config.listenHost = listen.at("host").get<std::string>();
        }
        if (listen.contains("port")) {
            config.listenPort = listen.at("port").get<int>();
        }
    }
    // A fleet is a messaging server, the node bound to it and the facades in
    // front. A config that just lists services is one fleet with no name, which
    // is what a single deployment looks like.
    const auto readServices = [](const nlohmann::json& list) {
        std::vector<ServiceEntry> services;
        for (const nlohmann::json& item : list) {
            ServiceEntry entry;
            entry.name = item.at("name").get<std::string>();
            entry.kind = item.at("kind").get<std::string>();
            entry.url = item.at("url").get<std::string>();
            if (!isKnownServiceKind(entry.kind)) {
                throw std::runtime_error("config: unknown service kind \"" + entry.kind + "\"");
            }
            services.push_back(std::move(entry));
        }
        return services;
    };

    if (json.contains("consumer")) {
        const nlohmann::json& consumer = json.at("consumer");
        config.consumer.name = consumer.value("name", std::string());
        config.consumer.place = consumer.value("place", std::string());
        config.consumer.role = consumer.value("role", std::string());
    }

    if (json.contains("fleets")) {
        for (const nlohmann::json& item : json.at("fleets")) {
            Fleet fleet;
            fleet.name = item.at("name").get<std::string>();
            fleet.services = readServices(item.at("services"));
            config.fleets.push_back(std::move(fleet));
        }
    } else if (json.contains("services")) {
        Fleet fleet;
        fleet.name = "server";
        fleet.services = readServices(json.at("services"));
        config.fleets.push_back(std::move(fleet));
    }

    // What the panel calls itself, when the operator has not said. A named
    // deployment lends its name: an operator running several panels needs to see
    // which one is asking.
    if (config.consumer.name.empty()) {
        config.consumer.name = "Bazarish admin panel";
        if (json.contains("fleets") && config.fleets.size() == 1
            && !config.fleets.front().name.empty()) {
            config.consumer.name += " - " + config.fleets.front().name;
        }
    }
    // Where it lives. The address it listens on is the one the operator opens,
    // unless the panel is fronted - and then the operator says so here.
    if (config.consumer.place.empty()) {
        config.consumer.place
            = "http://" + config.listenHost + ":" + std::to_string(config.listenPort);
    }
    if (config.consumer.role.empty()) {
        config.consumer.role = "Administrator";
    }
    return config;
}

Config Config::fromFile(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("config: cannot open " + path);
    }
    const std::string text(
        (std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return fromJson(text);
}

}  // namespace bazarish::admin
