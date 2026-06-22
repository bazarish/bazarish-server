// Bazarish project (c) 2026
#include "TransientPublisher.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

#include <ctime>
#include <exception>
#include <utility>

namespace bazarish::service {

namespace {

struct HostPort {
    std::string host;
    int port = 0;
};

// Splits "http://host:port" into host/port (default 80).
HostPort parseUrl(const std::string& url)
{
    std::string rest = url;
    const std::string scheme = "http://";
    if (rest.rfind(scheme, 0) == 0) {
        rest = rest.substr(scheme.size());
    }
    if (const auto slash = rest.find('/'); slash != std::string::npos) {
        rest = rest.substr(0, slash);
    }
    HostPort hostPort;
    if (const auto colon = rest.find(':'); colon == std::string::npos) {
        hostPort.host = rest;
        hostPort.port = 80;
    } else {
        hostPort.host = rest.substr(0, colon);
        hostPort.port = std::stoi(rest.substr(colon + 1));
    }
    return hostPort;
}

}  // namespace

TransientPublisher::TransientPublisher(
    std::string baseUrl, const Identity& signer, std::string endpointPath)
    : baseUrl_(std::move(baseUrl))
    , signer_(signer)
    , endpointPath_(std::move(endpointPath))
{
}

bool TransientPublisher::publish(const std::string& user, const std::string& transientB64,
    const std::int64_t expiresUnix) const
{
    if (baseUrl_.empty()) {
        return false;  // not configured
    }
    try {
        const HostPort hostPort = parseUrl(baseUrl_);
        httplib::Client client(hostPort.host, hostPort.port);
        client.set_connection_timeout(5, 0);
        client.set_read_timeout(10, 0);
        nlohmann::json body = {{"user", user}};
        if (!transientB64.empty()) {
            body["transient"] = transientB64;
            body["expiresUnix"] = expiresUnix;
        }
        const std::string bodyText = body.dump();
        const auth::Headers signature = auth::signRequest(signer_,
            static_cast<std::int64_t>(std::time(nullptr)), "PUT", endpointPath_,
            Bytes(bodyText.begin(), bodyText.end()));
        const httplib::Headers headers(signature.begin(), signature.end());
        const httplib::Result response
            = client.Put(endpointPath_, headers, bodyText, "application/json");
        return response && response->status == 200;
    } catch (const std::exception&) {
        return false;  // best effort
    }
}

}  // namespace bazarish::service
