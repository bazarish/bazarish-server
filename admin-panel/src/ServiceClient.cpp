// Bazarish project (c) 2026
#include "ServiceClient.hpp"

#include <bazarish/Tls.hpp>

#include <bazarish/GatewayProtocol.hpp>

#include <bazarish/Clock.hpp>
#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <bazarish/HttpClient.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <map>

namespace bazarish::admin {

namespace {

using bazarish::nowSeconds;

constexpr int kConnectTimeoutSeconds = 2;
constexpr int kExchangeTimeoutSeconds = 3;
bazarish::http::ClientOptions clientOptions()
{
    bazarish::http::ClientOptions options;
    options.connectTimeout = std::chrono::seconds(kConnectTimeoutSeconds);
    options.readTimeout = std::chrono::seconds(kExchangeTimeoutSeconds);
    options.writeTimeout = std::chrono::seconds(kExchangeTimeoutSeconds);
    return options;
}

bazarish::http::ClientResponse call(const ServiceEntry& service, const Identity& identity,
    const bazarish::tls::Credential& credential, const std::string& method,
    const std::string& target, const std::string& body)
{
    const bazarish::http::Url address = bazarish::http::parseUrl(service.url);
    const std::string full = address.path + target;
    const std::string path = full.substr(0, full.find('?'));
    const auth::Headers signature = auth::signRequest(
        identity, nowSeconds(), method, path, Bytes(body.begin(), body.end()));
    bazarish::http::ClientRequest out;
    out.method = method;
    out.target = full;
    out.headers = std::map<std::string, std::string>(signature.begin(), signature.end());
    if (!service.token.empty()) {
        out.headers[bazarish::gateway::kTokenHeader] = service.token;
    }
    out.body = body;
    if (!body.empty()) {
        out.contentType = "application/json";
    }
    bazarish::http::ClientOptions options = clientOptions();
    options.tls = address.tls;
    options.pin = service.pin;
    options.certificate = credential.certificate.string();
    options.key = credential.key.string();
    return bazarish::http::request(address.host, address.port, out, options);
}

std::string errorMessage(const bazarish::http::ClientResponse& result)
{
    if (result.status == 0) {
        return result.error;
    }
    try {
        const nlohmann::json body = nlohmann::json::parse(result.body);
        if (body.contains("error") && body.at("error").contains("message")) {
            return body.at("error").at("message").get<std::string>();
        }
    } catch (const std::exception&) {
        // error-hiding: allowed - not an error envelope, so the HTTP status below is the answer.
    }
    return "HTTP " + std::to_string(result.status);
}

}  // namespace

HealthResult probeHealth(const ServiceEntry& service, const Identity& identity,
    const bazarish::tls::Credential& credential)
{
    HealthResult out;

    const auto start = std::chrono::steady_clock::now();
    const bazarish::http::ClientResponse result
        = call(service, identity, credential, "GET", "/healthz", std::string());
    const auto end = std::chrono::steady_clock::now();
    out.latencyMs
        = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    if (result.status == 0) {
        out.error = result.error;
        return out;
    }
    out.status = result.status;
    if (result.status != 200) {
        out.error = errorMessage(result);
        return out;
    }
    try {
        const nlohmann::json body = nlohmann::json::parse(result.body);
        out.version = body.value("version", std::string());
        out.uptime = body.value("uptime", static_cast<std::int64_t>(0));
        out.ramBytes = body.value("ramBytes", static_cast<std::uint64_t>(0));
        out.ramPeakBytes = body.value("ramPeakBytes", static_cast<std::uint64_t>(0));
        out.requestsLastMinute = body.value("requestsLastMinute", static_cast<std::uint64_t>(0));
        out.requestsLastHour = body.value("requestsLastHour", static_cast<std::uint64_t>(0));
        out.requestsLastDay = body.value("requestsLastDay", static_cast<std::uint64_t>(0));
        out.inFlight = body.value("inFlight", static_cast<std::uint64_t>(0));
        out.sessions = body.value("sessions", static_cast<std::uint64_t>(0));
        out.destinations = body.value("destinations", static_cast<std::uint64_t>(0));
        out.streams = body.value("streams", static_cast<std::uint64_t>(0));
        out.refused = body.value("refused", static_cast<std::uint64_t>(0));
        out.router = body.value("i2pd", std::string());
        out.reachable = true;
    } catch (const std::exception& error) {
        out.error = std::string("bad health body: ") + error.what();
    }
    return out;
}

JsonResult callJson(const ServiceEntry& service, const Identity& identity,
    const bazarish::tls::Credential& credential, const std::string& method,
    const std::string& path, const std::string& body)
{
    const bazarish::http::ClientResponse response
        = call(service, identity, credential, method, path, body);
    JsonResult result;
    result.status = response.status;
    result.ok = response.status >= 200 && response.status < 300;
    result.body = response.body;
    if (!result.ok) {
        result.error = response.error.empty() ? response.body : response.error;
    }
    return result;
}

}  // namespace bazarish::admin
