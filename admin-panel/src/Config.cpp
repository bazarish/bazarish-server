// Bazarish project (c) 2026
#include "Config.hpp"

#include <nlohmann/json.hpp>

#include <fstream>
#include <stdexcept>

namespace bazarish::admin {

namespace {

const char* const kKnownKinds[]
    = {"server-core", "service-node", "facade", "alias-resolver"};

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
    if (json.contains("services")) {
        for (const nlohmann::json& item : json.at("services")) {
            ServiceEntry entry;
            entry.name = item.at("name").get<std::string>();
            entry.kind = item.at("kind").get<std::string>();
            entry.url = item.at("url").get<std::string>();
            if (!isKnownKind(entry.kind)) {
                throw std::runtime_error("config: unknown service kind \"" + entry.kind + "\"");
            }
            config.services.push_back(std::move(entry));
        }
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
