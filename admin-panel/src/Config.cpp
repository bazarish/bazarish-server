// Bazarish project (c) 2026
#include "Config.hpp"

#include <bazarish/JsonRead.hpp>
#include <bazarish/PrivateFile.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <iterator>
#include <set>
#include <stdexcept>

namespace bazarish::admin {

using bazarish::readFileText;

namespace {

const char* const kKnownKinds[]
    = {kServerCoreKind, kServiceNodeKind, kFacadeKind, kGatewayKind};

const char* const kKnownKeys[] = {"admin", "state", "assets", "listen", "consumer", "services"};

void requireKnownKeys(const nlohmann::json& json)
{
    if (!json.is_object()) {
        throw std::runtime_error("the config must be a JSON object");
    }
    for (const auto& item : json.items()) {
        const std::string& key = item.key();
        if (std::find(std::begin(kKnownKeys), std::end(kKnownKeys), key) == std::end(kKnownKeys)) {
            throw std::runtime_error("unknown config key \"" + key + "\"");
        }
    }
}

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

void requireCoherentServices(const std::vector<ServiceEntry>& services)
{
    std::set<std::string> names;
    std::size_t cores = 0;
    std::size_t nodes = 0;
    for (const ServiceEntry& service : services) {
        if (!names.insert(service.name).second) {
            throw std::invalid_argument("two services are named \""
                + service.name + "\": each needs a name of its own");
        }
        cores += service.kind == kServerCoreKind ? 1 : 0;
        nodes += service.kind == kServiceNodeKind ? 1 : 0;
    }
    if (cores > 1 || nodes > 1) {
        throw std::invalid_argument(
            "the panel holds one server-core and one service-node at most");
    }
}

nlohmann::json servicesJson(const std::vector<ServiceEntry>& services)
{
    nlohmann::json list = nlohmann::json::array();
    for (const ServiceEntry& service : services) {
        list.push_back({{"name", service.name}, {"kind", service.kind}, {"url", service.url},
            {"pin", service.pin}});
    }
    return list;
}

std::vector<ServiceEntry> servicesFromJson(const nlohmann::json& list)
{
    std::vector<ServiceEntry> services;
    for (const nlohmann::json& item : list) {
        ServiceEntry service;
        service.name = item.at("name").get<std::string>();
        service.kind = item.at("kind").get<std::string>();
        service.url = item.at("url").get<std::string>();
        service.pin = item.value("pin", std::string());
        if (!isKnownServiceKind(service.kind)) {
            throw std::invalid_argument(
                "the panel does not know a service of kind \"" + service.kind + "\"");
        }
        if (service.url.empty() || service.name.empty()) {
            throw std::invalid_argument("a service needs a name and a URL");
        }
        if (!service.url.starts_with("https://")) {
            throw std::invalid_argument("a service is reached over https: " + service.url);
        }
        if (service.pin.empty()) {
            throw std::invalid_argument(
                "a service is named by the key it presents: " + service.name);
        }
        services.push_back(std::move(service));
    }
    requireCoherentServices(services);
    return services;
}

Config Config::fromJson(const std::string& text)
{
    const nlohmann::json json = bazarish::parseJsonWithComments(text);
    requireKnownKeys(json);

    Config config;
    if (json.contains("admin")) {
        config.admins = json.at("admin").get<std::vector<std::string>>();
    }
    for (const std::string& fingerprint : config.admins) {
        if (fingerprint.empty()) {
            throw std::runtime_error("\"admin\" fingerprint must not be empty");
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
    if (json.contains("consumer")) {
        const nlohmann::json& consumer = json.at("consumer");
        config.consumer.name = consumer.value("name", std::string());
        config.consumer.place = consumer.value("place", std::vector<std::string>());
        config.consumer.role = consumer.value("role", std::string());
    }

    if (json.contains("services")) {
        config.services = servicesFromJson(json.at("services"));
    }

    if (config.consumer.name.empty()) {
        config.consumer.name = "Bazarish admin panel";
    }
    if (config.consumer.place.empty()) {
        config.consumer.place
            = {"http://" + config.listenHost + ":" + std::to_string(config.listenPort)};
    }
    if (config.consumer.role.empty()) {
        config.consumer.role = "Administrator";
    }
    return config;
}

Config Config::fromFile(const std::string& path)
{
    return fromJson(readFileText(std::filesystem::path(path)));
}

}  // namespace bazarish::admin
