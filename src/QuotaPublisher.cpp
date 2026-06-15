// Bazarish project (c) 2026
#include "QuotaPublisher.hpp"

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

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

QuotaPublisher::QuotaPublisher(
    std::string baseUrl, std::string operatorSecret, std::string endpointPath)
    : baseUrl_(std::move(baseUrl))
    , operatorSecret_(std::move(operatorSecret))
    , endpointPath_(std::move(endpointPath))
{
}

bool QuotaPublisher::publish(const std::string& user, const std::uint64_t quotaBytes) const
{
    if (baseUrl_.empty()) {
        return false;  // not configured
    }
    try {
        const HostPort hostPort = parseUrl(baseUrl_);
        httplib::Client client(hostPort.host, hostPort.port);
        client.set_connection_timeout(5, 0);
        client.set_read_timeout(10, 0);
        const nlohmann::json body = {{"user", user}, {"quotaBytes", quotaBytes}};
        const httplib::Headers headers = {{"X-Operator-Secret", operatorSecret_}};
        const httplib::Result response
            = client.Put(endpointPath_, headers, body.dump(), "application/json");
        return response && response->status == 200;
    } catch (const std::exception&) {
        return false;  // best effort
    }
}

}  // namespace bazarish::service
