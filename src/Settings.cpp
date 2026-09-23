// Bazarish project (c) 2026
#include "Settings.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>

namespace bazarish::gateway {

namespace {

// What nginx answers when it has nothing, byte for byte. A gateway that
// invented its own page would be a host that answers unlike any other.
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

}  // namespace

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
