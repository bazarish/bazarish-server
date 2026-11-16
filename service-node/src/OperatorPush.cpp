// Bazarish project (c) 2026
#include "OperatorPush.hpp"

#include <ServiceRoutes.hpp>
#include <OpsClient.hpp>

#include <bazarish/Auth.hpp>
#include <bazarish/JsonRead.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <bazarish/HttpClient.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <map>
#include <ctime>
#include <exception>
#include <utility>

namespace bazarish::service {

namespace {

constexpr int kConnectTimeoutSeconds = 5;
constexpr int kReadTimeoutSeconds = 30;
constexpr int kFirstServerErrorStatus = 500;

}  // namespace

OperatorPush::OperatorPush(Dial backend, const Identity& signer, std::function<void()> answered)
    : backend_(std::move(backend))
    , signer_(signer)
    , answered_(std::move(answered))
{
}

std::optional<MailboxUsage> OperatorPush::accountUsage(
    const std::string& user) const
{
    const bazarish::http::ClientResponse response
        = call("GET", std::string(routes::kMessagingAccount) + "?user=" + user, {});
    if (response.status != 200) {
        bazarish::log::warn("mailbox usage unavailable (HTTP {}): {}", response.status,
            response.error.empty() ? response.body : response.error);
        return std::nullopt;
    }
    try {
        const nlohmann::json body = bazarish::parseJson(response.body);
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

std::string OperatorPush::reseedArchive() const
{
    const bazarish::http::ClientResponse response = call("GET", "/internal/i2pseeds.su3", {});
    if (response.status != 200 || response.body.empty()) {
        bazarish::log::warn("the messaging server has no reseed archive (HTTP {}): {}",
            response.status, response.error.empty() ? response.body : response.error);
        return {};
    }
    return response.body;
}

std::optional<std::string> OperatorPush::putBody(
    const std::string& path, const std::string& bodyText) const
{
    return send("PUT", path, path, bodyText);
}

PushOutcome OperatorPush::forgetAccount(const std::string& user) const
{
    return exchange("DELETE", routes::kMessagingAccount,
        std::string(routes::kMessagingAccount) + "?user=" + user, std::string())
        .outcome;
}

bazarish::http::ClientResponse OperatorPush::call(const std::string& method,
    const std::string& pathAndQuery, const std::string& body) const
{
    const bazarish::http::ClientResponse response = server::opsCall(
        server::OpsTarget{backend_.url, backend_.pin, backend_.certificate, backend_.key}, signer_,
        method, pathAndQuery, body,
        server::OpsTimeouts{std::chrono::seconds(kConnectTimeoutSeconds),
            std::chrono::seconds(kReadTimeoutSeconds)});
    if (response.status > 0 && answered_) {
        answered_();
    }
    return response;
}

OperatorPush::Answer OperatorPush::exchange(const std::string& method, const std::string& path,
    const std::string& target, const std::string& bodyText) const
{
    try {
        const bazarish::http::ClientResponse response = call(method, target, bodyText);
        if (response.status == 200) {
            return {PushOutcome::eDelivered, response.body};
        }
        if (response.status > 0 && response.status < kFirstServerErrorStatus) {
            bazarish::log::warn("operator push to {}{} refused with {}: {}", backend_.url, path,
                response.status, response.body);
            return {PushOutcome::eRefused, {}};
        }
        bazarish::log::warn("operator push to {}{} did not land: {}", backend_.url, path,
            response.status > 0 ? std::to_string(response.status) : response.error);
    } catch (const std::exception& error) {
        bazarish::log::warn("operator push to {}{} failed: {}", backend_.url, path, error.what());
    }
    return {PushOutcome::eUnreachable, {}};
}

std::optional<std::string> OperatorPush::send(const std::string& method, const std::string& path,
    const std::string& target, const std::string& bodyText) const
{
    Answer answer = exchange(method, path, target, bodyText);
    if (answer.outcome != PushOutcome::eDelivered) {
        return std::nullopt;
    }
    return std::move(answer.body);
}

std::optional<Bytes> OperatorPush::nodeCard(const Bytes& sealingPublicKeyDer) const
{
    const nlohmann::json body = {{"sealingKey", toBase64(sealingPublicKeyDer)}};
    const std::optional<std::string> answer
        = send("POST", routes::kMessagingNodeCard, routes::kMessagingNodeCard, body.dump());
    if (!answer.has_value()) {
        return std::nullopt;
    }
    try {
        return fromBase64(bazarish::parseJson(*answer).at("card").get<std::string>());
    } catch (const std::exception& error) {
        bazarish::log::warn("the messaging server's answer with the node card is unreadable: {}",
            error.what());
        return std::nullopt;
    }
}

PushOutcome OperatorPush::publishQuota(
    const std::string& user, const std::uint64_t quotaBytes) const
{
    const nlohmann::json body = {{"user", user}, {"quotaBytes", quotaBytes}};
    return exchange("PUT", routes::kMessagingQuota, routes::kMessagingQuota, body.dump()).outcome;
}

PushOutcome OperatorPush::publishCardChanged(const std::string& user) const
{
    const std::string body = nlohmann::json{{"user", user}}.dump();
    return exchange("PUT", routes::kMessagingCard, routes::kMessagingCard, body).outcome;
}

PushOutcome OperatorPush::takeDownAddress(const std::string& user) const
{
    const std::string body = nlohmann::json{{"user", user}}.dump();
    return exchange("PUT", routes::kMessagingI2pDest, routes::kMessagingI2pDest, body).outcome;
}

std::optional<ServedDestination> OperatorPush::publish(const std::string& user,
    const std::string& transientB64, const std::int64_t expiresUnix,
    const AddressKeys& keys) const
{
    nlohmann::json body = {{"user", user}};
    if (!transientB64.empty()) {
        body["transient"] = transientB64;
        body["expiresUnix"] = expiresUnix;
        body["sealingKey"] = keys.sealingPem;
        body["signingKey"] = keys.signingPem;
    }
    const std::optional<std::string> answer = putBody(routes::kMessagingI2pDest, body.dump());
    if (!answer.has_value()) {
        return std::nullopt;
    }
    try {
        const nlohmann::json served = bazarish::parseJson(*answer);
        return ServedDestination{served.value("dest", std::string())};
    } catch (const std::exception& error) {
        bazarish::log::warn("the messaging server's answer about the destination of {} is "
                            "unreadable: {}",
            bazarish::log::redact(user), error.what());
        return std::nullopt;
    }
}

}  // namespace bazarish::service
