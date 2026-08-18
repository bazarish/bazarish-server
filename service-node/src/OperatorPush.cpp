// Bazarish project (c) 2026
#include "OperatorPush.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

#include <ctime>
#include <exception>
#include <utility>

namespace bazarish::service {

namespace {

constexpr int kConnectTimeoutSeconds = 5;
constexpr int kReadTimeoutSeconds = 10;

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

OperatorPush::OperatorPush(std::string baseUrl, const Identity& signer, std::string destPath,
    std::string quotaPath)
    : baseUrl_(std::move(baseUrl))
    , signer_(signer)
    , destPath_(std::move(destPath))
    , quotaPath_(std::move(quotaPath))
{
}

bool OperatorPush::put(const std::string& path, const std::string& bodyText) const
{
    if (baseUrl_.empty()) {
        return false;  // not configured
    }
    try {
        const HostPort hostPort = parseUrl(baseUrl_);
        httplib::Client client(hostPort.host, hostPort.port);
        client.set_connection_timeout(kConnectTimeoutSeconds, 0);
        client.set_read_timeout(kReadTimeoutSeconds, 0);
        const auth::Headers signature = auth::signRequest(signer_,
            static_cast<std::int64_t>(std::time(nullptr)), "PUT", path,
            Bytes(bodyText.begin(), bodyText.end()));
        const httplib::Headers headers(signature.begin(), signature.end());
        const httplib::Result response = client.Put(path, headers, bodyText, "application/json");
        if (!response) {
            bazarish::log::warn("operator push to {}{} did not connect: {}", baseUrl_, path,
                httplib::to_string(response.error()));
            return false;
        }
        if (response->status != 200) {
            bazarish::log::warn("operator push to {}{} refused with {}: {}", baseUrl_, path,
                response->status, response->body);
            return false;
        }
        return true;
    } catch (const std::exception& error) {
        bazarish::log::warn("operator push to {}{} failed: {}", baseUrl_, path, error.what());
        return false;
    }
}

bool OperatorPush::publishQuota(const std::string& user, const std::uint64_t quotaBytes) const
{
    const nlohmann::json body = {{"user", user}, {"quotaBytes", quotaBytes}};
    return put(quotaPath_, body.dump());
}

bool OperatorPush::publish(const std::string& user, const std::string& transientB64,
    const std::int64_t expiresUnix) const
{
    nlohmann::json body = {{"user", user}};
    if (!transientB64.empty()) {
        body["transient"] = transientB64;
        body["expiresUnix"] = expiresUnix;
    }
    return put(destPath_, body.dump());
}

}  // namespace bazarish::service
