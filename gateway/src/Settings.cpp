// Bazarish project (c) 2026
#include "Settings.hpp"

#include <bazarish/I2p.hpp>

#include <fstream>
#include <optional>
#include <sstream>
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

std::string readFile(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("cannot read " + path.string());
    }
    std::ostringstream text;
    text << file.rdbuf();
    return text.str();
}

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
    settings.token = config.text("token");
    if (settings.token.empty()) {
        throw std::runtime_error("\"token\" is mandatory");
    }
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

    settings.decoyMinBytes = static_cast<std::size_t>(
        config.number("decoy.minBytes", static_cast<std::int64_t>(kDecoyMinBytes)));
    settings.decoyMaxBytes = static_cast<std::size_t>(
        config.number("decoy.maxBytes", static_cast<std::int64_t>(kDecoyMaxBytes)));
    if (settings.decoyMinBytes == 0 || settings.decoyMinBytes > settings.decoyMaxBytes) {
        throw std::runtime_error("\"decoy.minBytes\" and \"decoy.maxBytes\" name a range");
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

    if (const std::string named = config.text("i2p.privacy"); !named.empty()) {
        const std::optional<i2p::Privacy> privacy = i2p::privacyFromString(named);
        if (!privacy.has_value()) {
            throw std::runtime_error("\"i2p.privacy\" is minimal, middle or max");
        }
        settings.tunnelPrivacy = *privacy;
    }
    settings.tunnelQuantity = static_cast<int>(
        config.number("i2p.tunnelQuantity", i2p::kDefaultTunnelQuantity));
    if (settings.tunnelQuantity < 1 || settings.tunnelQuantity > i2p::kMaxTunnelQuantity) {
        throw std::runtime_error("\"i2p.tunnelQuantity\" is between 1 and "
            + std::to_string(i2p::kMaxTunnelQuantity));
    }

    settings.streamPool = poolDepth(config, "pools.stream", kDefaultStreamPool);
    settings.callPool = poolDepth(config, "pools.call", kDefaultCallPool);

    settings.sessionTtlSeconds
        = config.number("sessionTtlSeconds", kSessionTtl.count());
    if (settings.sessionTtlSeconds <= 0) {
        throw std::runtime_error("\"sessionTtlSeconds\" is a term, not a switch");
    }

    const std::string notFoundFile = config.text("notFound");
    settings.notFoundBody
        = notFoundFile.empty() ? std::string(kNginxNotFound) : readFile(notFoundFile);
    const std::string serverName = config.text("serverName");
    if (!serverName.empty()) {
        settings.serverName = serverName;
    }
    return settings;
}

}  // namespace bazarish::gateway
