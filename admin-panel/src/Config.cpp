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

bool isKnownKind(const std::string& kind)
{
    for (const char* const known : kKnownKinds) {
        if (kind == known) {
            return true;
        }
    }
    return false;
}

}  // namespace

Config Config::fromJson(const std::string& text)
{
    const nlohmann::json json = nlohmann::json::parse(text, nullptr, true, true);

    Config config;
    const nlohmann::json& admin = json.at("admin");
    if (admin.is_array()) {
        config.admins = admin.get<std::vector<std::string>>();
    } else {
        config.admins = {admin.get<std::string>()};
    }
    if (config.admins.empty()) {
        throw std::runtime_error("config: \"admin\" must name at least one fingerprint");
    }
    for (const std::string& fingerprint : config.admins) {
        if (fingerprint.empty()) {
            throw std::runtime_error("config: \"admin\" fingerprint must not be empty");
        }
    }
    config.stateDir = json.value("state", std::string());
    config.assetsDir = json.value("assets", std::string());
    if (json.contains("audience")) {
        config.audience = json.at("audience").get<std::string>();
    }
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
            if (!isKnownKind(entry.kind)) {
                throw std::runtime_error("config: unknown service kind \"" + entry.kind + "\"");
            }
            services.push_back(std::move(entry));
        }
        return services;
    };

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
