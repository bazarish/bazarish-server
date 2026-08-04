// Bazarish project (c) 2026
#include "ServiceClient.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <ctime>

namespace bazarish::admin {

namespace {

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

httplib::Client makeClient(const std::string& url)
{
    httplib::Client client(url);
    client.set_connection_timeout(2, 0);
    client.set_read_timeout(3, 0);
    client.set_write_timeout(3, 0);
    return client;
}

// Signs (method, path, body) with the panel identity and returns the request-auth
// headers as httplib headers.
httplib::Headers signedHeaders(const Identity& identity, const std::string& method,
    const std::string& path, const std::string& body)
{
    const auth::Headers signature = auth::signRequest(
        identity, nowSeconds(), method, path, Bytes(body.begin(), body.end()));
    return httplib::Headers(signature.begin(), signature.end());
}

// Pulls a human message out of an error envelope body, falling back to the
// status line.
std::string errorMessage(const httplib::Result& result)
{
    if (!result) {
        return httplib::to_string(result.error());
    }
    try {
        const nlohmann::json body = nlohmann::json::parse(result->body);
        if (body.contains("error") && body.at("error").contains("message")) {
            return body.at("error").at("message").get<std::string>();
        }
    } catch (const std::exception&) {
        // Not an envelope; fall through.
    }
    return "HTTP " + std::to_string(result->status);
}

OpResult putJson(const ServiceEntry& service, const Identity& identity, const std::string& path,
    const nlohmann::json& body)
{
    httplib::Client client = makeClient(service.url);
    const std::string bodyText = body.dump();
    const httplib::Result result
        = client.Put(path.c_str(), signedHeaders(identity, "PUT", path, bodyText), bodyText,
            "application/json");

    OpResult out;
    if (!result) {
        out.message = httplib::to_string(result.error());
        return out;
    }
    out.status = result->status;
    out.ok = result->status == 200;
    out.message = out.ok ? "ok" : errorMessage(result);
    return out;
}

}  // namespace

HealthResult probeHealth(const ServiceEntry& service, const Identity& identity)
{
    HealthResult out;
    httplib::Client client = makeClient(service.url);

    const auto start = std::chrono::steady_clock::now();
    const httplib::Result result
        = client.Get("/healthz", signedHeaders(identity, "GET", "/healthz", std::string()));
    const auto end = std::chrono::steady_clock::now();
    out.latencyMs
        = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    if (!result) {
        out.error = httplib::to_string(result.error());
        return out;
    }
    out.status = result->status;
    if (result->status != 200) {
        out.error = errorMessage(result);
        return out;
    }
    try {
        const nlohmann::json body = nlohmann::json::parse(result->body);
        out.version = body.value("version", std::string());
        out.uptime = body.value("uptime", static_cast<std::int64_t>(0));
        out.ramBytes = body.value("ramBytes", static_cast<std::uint64_t>(0));
        out.ramPeakBytes = body.value("ramPeakBytes", static_cast<std::uint64_t>(0));
        out.reachable = true;
    } catch (const std::exception& error) {
        out.error = std::string("bad health body: ") + error.what();
    }
    return out;
}

OpResult setQuota(const ServiceEntry& service, const Identity& identity, const std::string& user,
    const std::uint64_t quotaBytes)
{
    const std::string path
        = service.kind == "blob-storage" ? "/v1/storage/quota" : "/v1/messaging/quota";
    return putJson(service, identity, path, {{"user", user}, {"quotaBytes", quotaBytes}});
}

OpResult setI2pDest(const ServiceEntry& service, const Identity& identity,
    const std::string& user, const std::string& transientBase64, const std::int64_t expiresUnix)
{
    return putJson(service, identity, "/v1/messaging/i2p-dest",
        {{"user", user}, {"transient", transientBase64}, {"expiresUnix", expiresUnix}});
}

PendingResult listPending(const ServiceEntry& service, const Identity& identity)
{
    const std::string path = "/v1/account/pending";
    httplib::Client client = makeClient(service.url);
    const httplib::Result result
        = client.Get(path.c_str(), signedHeaders(identity, "GET", path, std::string()));

    PendingResult out;
    if (!result) {
        out.error = httplib::to_string(result.error());
        return out;
    }
    if (result->status != 200) {
        out.error = errorMessage(result);
        return out;
    }
    try {
        for (const nlohmann::json& entry : nlohmann::json::parse(result->body).at("pending")) {
            out.accounts.push_back({entry.at("user").get<std::string>(),
                entry.value("requestedAt", static_cast<std::int64_t>(0))});
        }
        out.ok = true;
    } catch (const std::exception& error) {
        out.error = std::string("bad pending body: ") + error.what();
    }
    return out;
}

OpResult approveAccount(
    const ServiceEntry& service, const Identity& identity, const std::string& user)
{
    const std::string path = "/v1/account/approve";
    httplib::Client client = makeClient(service.url);
    const std::string bodyText = nlohmann::json{{"user", user}}.dump();
    const httplib::Result result = client.Post(
        path.c_str(), signedHeaders(identity, "POST", path, bodyText), bodyText,
        "application/json");

    OpResult out;
    if (!result) {
        out.message = httplib::to_string(result.error());
        return out;
    }
    out.status = result->status;
    out.ok = result->status == 200;
    out.message = out.ok ? "ok" : errorMessage(result);
    return out;
}

}  // namespace bazarish::admin
