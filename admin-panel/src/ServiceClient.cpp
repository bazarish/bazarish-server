// Bazarish project (c) 2026
#include "ServiceClient.hpp"

#include <bazarish/GatewayProtocol.hpp>

#include <bazarish/Clock.hpp>
#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <bazarish/HttpClient.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <map>
#include <ctime>

namespace bazarish::admin {

namespace {

using bazarish::nowSeconds;

// The panel and the services it manages sit on the same machine, so a request
// that takes this long is a service that is down, not a busy one.
constexpr int kConnectTimeoutSeconds = 2;
constexpr int kExchangeTimeoutSeconds = 3;
// The port a service URL means when it names none.
constexpr int kDefaultHttpPort = 80;
constexpr int kDefaultHttpsPort = 443;

// Where a service URL points: the client takes a host and a port, not a URL.
// A gateway also carries the path it answers at, and may be reached over TLS -
// it is the one service that need not be on this machine.
struct Address {
    std::string host;
    int port = kDefaultHttpPort;
    std::string path;
    bool tls = false;
};

Address parseUrl(const std::string& url)
{
    std::string rest = url;
    Address address;
    if (const std::string scheme = "https://"; rest.rfind(scheme, 0) == 0) {
        rest = rest.substr(scheme.size());
        address.tls = true;
        address.port = kDefaultHttpsPort;
    } else if (const std::string plain = "http://"; rest.rfind(plain, 0) == 0) {
        rest = rest.substr(plain.size());
    }
    if (const auto slash = rest.find('/'); slash != std::string::npos) {
        address.path = rest.substr(slash);
        rest = rest.substr(0, slash);
    }
    if (const auto colon = rest.find(':'); colon == std::string::npos) {
        address.host = rest;
    } else {
        address.host = rest.substr(0, colon);
        address.port = std::stoi(rest.substr(colon + 1));
    }
    return address;
}

bazarish::http::ClientOptions clientOptions()
{
    bazarish::http::ClientOptions options;
    options.connectTimeout = std::chrono::seconds(kConnectTimeoutSeconds);
    options.readTimeout = std::chrono::seconds(kExchangeTimeoutSeconds);
    options.writeTimeout = std::chrono::seconds(kExchangeTimeoutSeconds);
    return options;
}

// One signed request to a service, whatever the method. The signature covers the
// query-less path, which is what every service verifies: a signature over the
// query string would be refused the moment the panel searched for anything.
bazarish::http::ClientResponse call(const ServiceEntry& service, const Identity& identity,
    const std::string& method, const std::string& target, const std::string& body)
{
    const Address address = parseUrl(service.url);
    // A gateway answers under a path nobody guesses, and the signature has to
    // cover the path the service will verify - which is the whole of it.
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
    return bazarish::http::request(address.host, address.port, out, options);
}

// Pulls a human message out of an error envelope body, falling back to the
// status line.
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
        // Not an error envelope: the HTTP status below is the whole answer, so
        // nothing is lost - the parse failure IS the information.
    }
    return "HTTP " + std::to_string(result.status);
}

}  // namespace

HealthResult probeHealth(const ServiceEntry& service, const Identity& identity)
{
    HealthResult out;

    const auto start = std::chrono::steady_clock::now();
    const bazarish::http::ClientResponse result
        = call(service, identity, "GET", "/healthz", std::string());
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
        // A facade adds what it is carrying; nobody else reports these.
        out.requestsLastMinute = body.value("requestsLastMinute", static_cast<std::uint64_t>(0));
        out.requestsLastHour = body.value("requestsLastHour", static_cast<std::uint64_t>(0));
        out.requestsLastDay = body.value("requestsLastDay", static_cast<std::uint64_t>(0));
        out.inFlight = body.value("inFlight", static_cast<std::uint64_t>(0));
        // The server adds what only it has: warm destinations to send from.
        out.reachable = true;
    } catch (const std::exception& error) {
        out.error = std::string("bad health body: ") + error.what();
    }
    return out;
}

JsonResult callJson(const ServiceEntry& service, const Identity& identity,
    const std::string& method, const std::string& path, const std::string& body)
{
    const bazarish::http::ClientResponse response = call(service, identity, method, path, body);
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
