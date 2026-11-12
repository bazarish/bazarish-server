// Bazarish project (c) 2026
#include "NodeCards.hpp"

#include <ServiceRoutes.hpp>

#include <bazarish/KeyedSeal.hpp>
#include <bazarish/Auth.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/HttpClient.hpp>
#include <bazarish/JsonRead.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>

namespace bazarish::server {

namespace {

constexpr int kFound = 200;
constexpr int kNotFound = 404;

}  // namespace

NodeCards::NodeCards(NodeAddress node, std::shared_ptr<const Identity> identity)
    : node_(std::move(node))
    , identity_(std::move(identity))
{
}

std::optional<HeldCard> NodeCards::card(const std::string& user)
{
    const std::int64_t now = nowSeconds();
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto found = cached_.find(user);
        if (found != cached_.end() && now - found->second.first < kCacheSeconds) {
            return found->second.second;
        }
    }
    http::ClientRequest lookup;
    lookup.method = "GET";
    lookup.target = std::string(routes::kAccountCard) + "?user=" + user;
    lookup.headers = auth::signRequest(*identity_, now, "GET", lookup.target, {});
    http::ClientOptions options;
    options.tls = node_.tls;
    options.pin = node_.pin;
    options.connectTimeout = kTimeout;
    options.readTimeout = kTimeout;
    options.writeTimeout = kTimeout;
    const http::ClientResponse answer = http::request(node_.host, node_.port, lookup, options);
    if (answer.status == kNotFound) {
        return std::nullopt;
    }
    if (answer.status != kFound) {
        throw std::runtime_error(
            "the service node answered a card lookup with HTTP " + std::to_string(answer.status));
    }
    const nlohmann::json found = parseJson(answer.body);
    const HeldCard card{fromBase64(found.at("card").get<std::string>()),
        linkKeyFromText(found.at("cardKey").get<std::string>())};
    const std::lock_guard<std::mutex> lock(mutex_);
    cached_[user] = {now, card};
    return card;
}

void NodeCards::forget(const std::string& user)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    cached_.erase(user);
}

}  // namespace bazarish::server
