// Bazarish project (c) 2026
#include "OpsClient.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Clock.hpp>

#include <map>

namespace bazarish::server {

http::ClientResponse opsCall(const OpsTarget& target, const Identity& signer,
    const std::string& method, const std::string& pathAndQuery, const std::string& body,
    const OpsTimeouts& timeouts)
{
    const http::Url address = http::parseUrl(target.url);
    const std::string full = address.path + pathAndQuery;
    const std::string path = full.substr(0, full.find('?'));
    const auth::Headers signature
        = auth::signRequest(signer, nowSeconds(), method, path, Bytes(body.begin(), body.end()));
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
    return http::request(address.host, address.port, out, options);
}

}  // namespace bazarish::server
