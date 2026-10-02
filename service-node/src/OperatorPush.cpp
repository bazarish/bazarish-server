// Bazarish project (c) 2026
#include "OperatorPush.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <bazarish/HttpClient.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <map>
#include <ctime>
#include <thread>
#include <exception>
#include <utility>

namespace bazarish::service {

namespace {

constexpr int kConnectTimeoutSeconds = 5;
constexpr int kReadTimeoutSeconds = 30;
// The messaging server is the operator's own, one hop away: a push that does not
// land is almost always it being momentarily busy (bringing another destination
// up, say), not a refusal. Retry before handing the user an error they can do
// nothing about; a real refusal (4xx) is final and is not retried.
constexpr int kRetryDelaySeconds = 1;
// How often the readiness wait asks again. Short: the two daemons come up
// together, so this is usually over in one or two tries.
constexpr int kReadyPollSeconds = 1;
constexpr int kFirstServerErrorStatus = 500;

// The messaging server's operator endpoints. Protocol, not configuration: the
// server that answers them is the one this node is bound to by its card.
constexpr const char* kDestPath = "/v1/messaging/i2p-dest";
constexpr const char* kQuotaPath = "/v1/messaging/quota";
constexpr const char* kServingKeyPath = "/v1/messaging/serving-key";
constexpr const char* kAccountPath = "/v1/messaging/account";

}  // namespace

OperatorPush::OperatorPush(std::string baseUrl, const Identity& signer, const int attempts)
    : baseUrl_(std::move(baseUrl))
    , signer_(signer)
    , attempts_(attempts)
{
}

bool OperatorPush::waitReachable(const std::chrono::seconds budget) const
{
    if (baseUrl_.empty()) {
        return false;  // nothing configured to wait for
    }
    const std::chrono::steady_clock::time_point deadline
        = std::chrono::steady_clock::now() + budget;
    bool waited = false;
    // Kept so the give-up below can say what was in the way, rather than only
    // that something was.
    std::string lastError;
    while (true) {
        try {
            const bazarish::http::Url target = bazarish::http::parseUrl(baseUrl_);
            bazarish::http::ClientRequest ask;
            ask.method = "GET";
            // Unsigned on purpose: a 403 is as good an answer as a 200 here, and
            // it costs the messaging server nothing to give.
            ask.target = "/healthz";
            bazarish::http::ClientOptions options;
            options.connectTimeout = std::chrono::seconds(kConnectTimeoutSeconds);
            options.readTimeout = std::chrono::seconds(kReadTimeoutSeconds);
            const bazarish::http::ClientResponse response
                = bazarish::http::request(target.host, target.port, ask, options);
            if (response.status > 0) {
                if (waited) {
                    bazarish::log::info("the messaging server is answering");
                }
                return true;
            }
            lastError = response.error;
        } catch (const std::exception& error) {
            lastError = error.what();
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            bazarish::log::warn("the messaging server at {} is not answering ({}); what this "
                                "node has for it will be pushed when it is",
                baseUrl_, lastError.empty() ? std::string("no answer") : lastError);
            return false;
        }
        if (!waited) {
            bazarish::log::info("waiting for the messaging server at {}", baseUrl_);
            waited = true;
        }
        std::this_thread::sleep_for(std::chrono::seconds(kReadyPollSeconds));
    }
}

std::optional<MailboxUsage> OperatorPush::accountUsage(
    const std::string& user) const
{
    if (baseUrl_.empty()) {
        return std::nullopt;  // not configured
    }
    const std::string path = "/v1/messaging/account";
    const bazarish::http::Url target = bazarish::http::parseUrl(baseUrl_);
    const auth::Headers signature = auth::signRequest(
        signer_, static_cast<std::int64_t>(std::time(nullptr)), "GET", path, Bytes());
    bazarish::http::ClientRequest ask;
    ask.method = "GET";
    ask.target = path + "?user=" + user;
    ask.headers = std::map<std::string, std::string>(signature.begin(), signature.end());
    bazarish::http::ClientOptions options;
    options.connectTimeout = std::chrono::seconds(kConnectTimeoutSeconds);
    options.readTimeout = std::chrono::seconds(kReadTimeoutSeconds);
    const bazarish::http::ClientResponse response
        = bazarish::http::request(target.host, target.port, ask, options);
    if (response.status != 200) {
        bazarish::log::warn("mailbox usage unavailable (HTTP {}): {}", response.status,
            response.error.empty() ? response.body : response.error);
        return std::nullopt;
    }
    try {
        const nlohmann::json body = nlohmann::json::parse(response.body);
        MailboxUsage usage;
        usage.usedBytes = body.at("usedBytes").get<std::uint64_t>();
        usage.quotaBytes = body.at("quotaBytes").get<std::uint64_t>();
        usage.devices = body.at("devices").get<std::size_t>();
        return usage;
    } catch (const std::exception& error) {
        bazarish::log::warn("mailbox usage unreadable: {}", error.what());
        return std::nullopt;
    }
}

bool OperatorPush::put(const std::string& path, const std::string& bodyText) const
{
    return putBody(path, bodyText).has_value();
}

std::optional<std::string> OperatorPush::putBody(
    const std::string& path, const std::string& bodyText) const
{
    return send("PUT", path, path, bodyText);
}

bool OperatorPush::forgetMailbox(const std::string& user) const
{
    return send("DELETE", kAccountPath, std::string(kAccountPath) + "?user=" + user, std::string())
        .has_value();
}

std::optional<std::string> OperatorPush::send(const std::string& method, const std::string& path,
    const std::string& target, const std::string& bodyText) const
{
    if (baseUrl_.empty()) {
        return std::nullopt;  // not configured
    }
    for (int attempt = 1; attempt <= attempts_; ++attempt) {
        try {
            const bazarish::http::Url backend = bazarish::http::parseUrl(baseUrl_);
            // Signed per attempt: the signature covers a timestamp.
            const auth::Headers signature = auth::signRequest(signer_,
                static_cast<std::int64_t>(std::time(nullptr)), method, path,
                Bytes(bodyText.begin(), bodyText.end()));
            bazarish::http::ClientRequest push;
            push.method = method;
            push.target = target;
            push.headers = std::map<std::string, std::string>(signature.begin(), signature.end());
            push.body = bodyText;
            push.contentType = "application/json";
            bazarish::http::ClientOptions options;
            options.connectTimeout = std::chrono::seconds(kConnectTimeoutSeconds);
            options.readTimeout = std::chrono::seconds(kReadTimeoutSeconds);
            const bazarish::http::ClientResponse response
                = bazarish::http::request(backend.host, backend.port, push, options);
            if (response.status == 200) {
                return response.body;
            }
            if (response.status > 0 && response.status < kFirstServerErrorStatus) {
                bazarish::log::warn("operator push to {}{} refused with {}: {}", baseUrl_, path,
                    response.status, response.body);
                return std::nullopt;  // a refusal, not a hiccup: retrying changes nothing
            }
            bazarish::log::warn("operator push to {}{} did not land (attempt {}/{}): {}", baseUrl_,
                path, attempt, attempts_,
                response.status > 0 ? std::to_string(response.status) : response.error);
        } catch (const std::exception& error) {
            bazarish::log::warn("operator push to {}{} failed (attempt {}/{}): {}", baseUrl_, path,
                attempt, attempts_, error.what());
        }
        if (attempt < attempts_) {
            std::this_thread::sleep_for(std::chrono::seconds(kRetryDelaySeconds));
        }
    }
    return std::nullopt;
}

bool OperatorPush::publishQuota(const std::string& user, const std::uint64_t quotaBytes) const
{
    const nlohmann::json body = {{"user", user}, {"quotaBytes", quotaBytes}};
    return put(kQuotaPath, body.dump());
}

std::optional<std::string> OperatorPush::prepareServingKey(const std::string& user) const
{
    const nlohmann::json body = {{"user", user}, {"phase", "prepare"}};
    const std::optional<std::string> answer = putBody(kServingKeyPath, body.dump());
    if (!answer.has_value()) {
        return std::nullopt;
    }
    const nlohmann::json parsed = nlohmann::json::parse(*answer);
    return parsed.at("servingKey").get<std::string>();
}

bool OperatorPush::commitServingKey(const std::string& user) const
{
    const nlohmann::json body = {{"user", user}, {"phase", "commit"}};
    return put(kServingKeyPath, body.dump());
}

bool OperatorPush::publish(const std::string& user, const std::string& transientB64,
    const std::int64_t expiresUnix) const
{
    nlohmann::json body = {{"user", user}};
    if (!transientB64.empty()) {
        body["transient"] = transientB64;
        body["expiresUnix"] = expiresUnix;
    }
    return put(kDestPath, body.dump());
}

}  // namespace bazarish::service
