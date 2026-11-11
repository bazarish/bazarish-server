// Bazarish project (c) 2026
#include "OpsClient.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Clock.hpp>

#include <map>
#include <utility>

namespace bazarish::server {

OpsExchange opsExchange(const OpsTarget& target, const Identity& signer,
    const std::string& method, const std::string& pathAndQuery, const std::string& body,
    const OpsTimeouts& timeouts)
{
    const http::Url address = http::parseUrl(target.url);
    const std::string full = address.path + pathAndQuery;
    const auth::Headers signature
        = auth::signRequest(signer, nowSeconds(), method, full, Bytes(body.begin(), body.end()));
    http::ClientRequest out;
    out.method = method;
    out.target = full;
    out.headers = std::map<std::string, std::string>(signature.begin(), signature.end());
    out.body = body;
    if (!body.empty()) {
        out.contentType = "application/json";
    }
    http::ClientOptions options;
    options.tls = address.tls;
    options.pin = target.pin;
    options.certificate = target.certificate;
    options.key = target.key;
    options.connectTimeout = timeouts.connect;
    options.readTimeout = timeouts.exchange;
    options.writeTimeout = timeouts.exchange;
    return OpsExchange{address.host, address.port, std::move(out), std::move(options)};
}

http::ClientResponse opsCall(const OpsTarget& target, const Identity& signer,
    const std::string& method, const std::string& pathAndQuery, const std::string& body,
    const OpsTimeouts& timeouts)
{
    const OpsExchange exchange = opsExchange(target, signer, method, pathAndQuery, body, timeouts);
    return http::request(exchange.host, exchange.port, exchange.request, exchange.options);
}

}  // namespace bazarish::server
