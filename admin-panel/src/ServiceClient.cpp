// Bazarish project (c) 2026
#include "ServiceClient.hpp"

#include <OpsClient.hpp>

#include <bazarish/JsonRead.hpp>
#include <bazarish/Tls.hpp>

#include <bazarish/Clock.hpp>
#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Errors.hpp>

#include <bazarish/HttpClient.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <map>

namespace bazarish::admin {

namespace {

constexpr int kConnectTimeoutSeconds = 2;
constexpr int kExchangeTimeoutSeconds = 3;

bazarish::http::ClientResponse call(const ServiceEntry& service, const Identity& identity,
    const bazarish::tls::Credential& credential, const std::string& method,
    const std::string& target, const std::string& body)
{
    return bazarish::server::opsCall(
        bazarish::server::OpsTarget{service.url, service.pin, credential.certificate.string(),
            credential.key.string()},
        identity, method, target, body,
        bazarish::server::OpsTimeouts{std::chrono::seconds(kConnectTimeoutSeconds),
            std::chrono::seconds(kExchangeTimeoutSeconds)});
}

std::string errorMessage(const bazarish::http::ClientResponse& result)
{
    if (result.status == 0) {
        return result.error;
    }
    const std::optional<bazarish::ParsedError> envelope
        = bazarish::parseErrorEnvelope(bazarish::parseJsonOrDiscarded(result.body));
    if (envelope.has_value() && !envelope->message.empty()) {
        return envelope->message;
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
        const nlohmann::json body = bazarish::parseJson(result.body);
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

std::string failureText(const JsonResult& result)
{
    if (result.status == 0) {
        return result.error;
    }
    try {
        const nlohmann::json body = bazarish::parseJson(result.body);
        const nlohmann::json& error = body.at("error");
        if (error.is_string()) {
            return error.get<std::string>();
        }
        return error.at("message").get<std::string>();
    } catch (const std::exception&) {
        // error-hiding: allowed - not an error envelope, so the HTTP status below is the answer.
    }
    return "HTTP " + std::to_string(result.status);
}

}  // namespace bazarish::admin
