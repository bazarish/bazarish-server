// Bazarish project (c) 2026
#include "Settings.hpp"

#include <OpsSettings.hpp>

#include <bazarish/I2p.hpp>
#include <bazarish/Links.hpp>
#include <bazarish/PrivateFile.hpp>

#include <optional>
#include <stdexcept>
#include <string>

namespace bazarish::gateway {

namespace {

constexpr const char* kNginxNotFound = "<html>\r\n"
                                       "<head><title>404 Not Found</title></head>\r\n"
                                       "<body>\r\n"
                                       "<center><h1>404 Not Found</h1></center>\r\n"
                                       "<hr><center>nginx</center>\r\n"
                                       "</body>\r\n"
                                       "</html>\r\n";

constexpr const char* kSecureScheme = "https://";
constexpr const char* kPlainScheme = "http://";
constexpr const char* kNotInAuthority = "/?#& \t\r\n";

std::size_t poolDepth(const ConfigView& config, const std::string& path, const std::size_t fallback)
{
    const std::int64_t depth
        = config.number(path, static_cast<std::int64_t>(fallback));
    if (depth < 0 || depth > static_cast<std::int64_t>(kMaxPoolDepth)) {
        throw std::runtime_error("\"" + path + "\" is between 0 and "
            + std::to_string(kMaxPoolDepth));
    }
    return static_cast<std::size_t>(depth);
}

}  // namespace

shape::LogNormalMixture defaultDecoyPage()
{
    return {{{1, kDecoyPageMedianBytes, kDecoyPageSigma}}, kDecoyMinBytes, kDecoyMaxBytes};
}

shape::LogNormalMixture defaultDecoyResource()
{
    return {{{1, kDecoyResourceMedianBytes, kDecoyResourceSigma}}, kDecoyMinBytes, kDecoyMaxBytes};
}

shape::LogNormalMixture decoyMixtureFrom(const nlohmann::json& item, const std::string& name)
{
    shape::LogNormalMixture mixture;
    mixture.min = kDecoyMinBytes;
    mixture.max = item.at("maxBytes").get<double>();
    for (const nlohmann::json& part : item.at("parts")) {
        mixture.parts.push_back({part.at("weight").get<double>(),
            part.at("medianBytes").get<double>(), part.at("sigma").get<double>()});
    }
    try {
        shape::validate(mixture);
    } catch (const std::invalid_argument& error) {
        throw std::runtime_error("\"decoy." + name + "\": " + error.what());
    }
    return mixture;
}

std::string publicAddressFrom(const std::string& text)
{
    if (text.empty()) {
        return text;
    }
    std::string rest;
    for (const char* const scheme : {kSecureScheme, kPlainScheme}) {
        if (text.starts_with(scheme)) {
            rest = text.substr(std::string(scheme).size());
        }
    }
    if (rest.empty() || rest.find_first_of(kNotInAuthority) != std::string::npos) {
        throw std::invalid_argument("\"publicAddress\" is http(s)://host or http(s)://host:port, "
                                    "with no path");
    }
    return text;
}

std::string clientLink(const Settings& settings, const std::string& fingerprint)
{
    if (settings.publicAddress.empty()) {
        return {};
    }
    return gatewayLink(settings.publicAddress + settings.basePath, fingerprint);
}

std::vector<DirectRoute> directRoutesFrom(const nlohmann::json& list)
{
    std::vector<DirectRoute> routes;
    for (const nlohmann::json& item : list) {
        DirectRoute route;
        route.dest = item.value("dest", std::string());
        route.host = item.value("host", std::string());
        route.port = item.value("port", 0);
        route.pin = item.value("pin", std::string());
        if (route.dest.empty() || route.host.empty() || route.port <= 0 || route.pin.empty()) {
            throw std::runtime_error(
                "\"direct\" names a destination, an address and the key it presents");
        }
        routes.push_back(std::move(route));
    }
    return routes;
}

std::optional<ServerLink> serverLinkFrom(const nlohmann::json& link)
{
    if (link.is_null()) {
        return std::nullopt;
    }
    ServerLink server;
    server.host = link.value("host", std::string());
    server.port = link.value("port", 0);
    server.pin = link.value("pin", std::string());
    if (server.host.empty() || server.port <= 0 || server.pin.empty()) {
        throw std::runtime_error("\"server\" names an address and the key it presents");
    }
    return server;
}

Settings Settings::from(const ConfigView& config)
{
    Settings settings;
    const std::optional<ConfigView::Endpoint> listen = config.endpoint("listen");
    if (listen.has_value()) {
        settings.listenHost = listen->host;
        settings.listenPort = listen->port;
    }

    settings.basePath = config.text("basePath");
    if (settings.basePath.empty() || settings.basePath.front() != '/') {
        throw std::runtime_error("\"basePath\" is mandatory and starts with a slash");
    }
    settings.publicAddress = publicAddressFrom(config.text("publicAddress"));
    settings.stateDir = std::filesystem::path(config.text("state"));
    if (settings.stateDir.empty()) {
        throw std::runtime_error("\"state\" is mandatory: the router keeps everything under it");
    }

    for (const std::string& url : config.list("reseed")) {
        if (!i2p::isReseedUrl(url)) {
            throw std::runtime_error("\"reseed\" holds " + url + ", not an https URL");
        }
        settings.reseedUrls.push_back(url);
    }

    if (const auto decoy = config.document().find("decoy"); decoy != config.document().end()) {
        if (const auto page = decoy->find("page"); page != decoy->end()) {
            settings.decoyPage = decoyMixtureFrom(*page, "page");
        }
        if (const auto resource = decoy->find("resource"); resource != decoy->end()) {
            settings.decoyResource = decoyMixtureFrom(*resource, "resource");
        }
    }

    for (const std::string& fingerprint : config.list("operators")) {
        settings.operators.push_back(fingerprint);
    }

    if (const std::optional<ConfigView::Endpoint> ops = config.endpoint("opsListen");
        ops.has_value()) {
        settings.opsHost = ops->host;
        settings.opsPort = ops->port;
    }
    for (const std::string& pin : config.list("opsClients")) {
        settings.opsClients.push_back(pin);
    }

    const nlohmann::json& document = config.document();
    if (document.contains("direct")) {
        settings.direct = directRoutesFrom(document.at("direct"));
    }
    if (document.contains("server")) {
        settings.server = serverLinkFrom(document.at("server"));
    }

    settings.tunnelPrivacy = server::configPrivacy(config, settings.tunnelPrivacy);
    settings.logLevel = server::configLogLevel(config);
    settings.i2pLogLevel = server::configI2pLogLevel(config);

    settings.streamPool = poolDepth(config, "pools.stream", kDefaultStreamPool);
    settings.callPool = poolDepth(config, "pools.call", kDefaultCallPool);
    settings.watchPool = poolDepth(config, "pools.watch", kDefaultWatchPool);

    settings.sessionTtlSeconds
        = config.number("sessionTtlSeconds", kSessionTtl.count());
    if (settings.sessionTtlSeconds <= 0) {
        throw std::runtime_error("\"sessionTtlSeconds\" is a term, not a switch");
    }

    const std::string notFoundFile = config.text("notFound");
    settings.notFoundBody
        = notFoundFile.empty() ? std::string(kNginxNotFound) : readFileText(notFoundFile);
    const std::string serverName = config.text("serverName");
    if (!serverName.empty()) {
        settings.serverName = serverName;
    }
    return settings;
}

}  // namespace bazarish::gateway
