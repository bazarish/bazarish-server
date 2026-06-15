// Bazarish project (c) 2026
#include "PortalApi.hpp"

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

#include <ctime>
#include <exception>
#include <utility>

namespace {

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

void respondJson(httplib::Response& response, const nlohmann::json& body)
{
    response.set_content(body.dump(), "application/json");
}

// Reads one cookie value from the request's Cookie header.
std::string cookieValue(const httplib::Request& request, const std::string& name)
{
    const std::string cookies = request.get_header_value("Cookie");
    const std::string key = name + "=";
    const auto pos = cookies.find(key);
    if (pos == std::string::npos) {
        return {};
    }
    const auto start = pos + key.size();
    const auto end = cookies.find(';', start);
    return cookies.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

}  // namespace

namespace bazarish::service {

PortalApi::PortalApi(PortalApiOptions options)
    : options_(std::move(options))
    , login_(options_.challengeSecret, options_.audience)
    , session_(options_.sessionSecret, options_.sessionTtlSeconds)
    , http_(std::make_unique<httplib::Server>())
{
    setupRoutes();
}

PortalApi::~PortalApi() = default;

bool PortalApi::listen(const std::string& host, const int port)
{
    return http_->listen(host, port);
}

int PortalApi::bindToAnyPort(const std::string& host)
{
    return http_->bind_to_any_port(host);
}

bool PortalApi::listenAfterBind()
{
    return http_->listen_after_bind();
}

void PortalApi::stop()
{
    http_->stop();
}

void PortalApi::setupRoutes()
{
    // Issue a fresh login challenge for the user to sign with their Client.
    http_->Get("/portal/login", [this](const httplib::Request&, httplib::Response& response) {
        respondJson(response, {{"challenge", login_.issue(nowSeconds())}});
    });

    // Verify the signed challenge and start a session.
    http_->Post("/portal/login", [this](const httplib::Request& request,
                                      httplib::Response& response) {
        const nlohmann::json body = nlohmann::json::parse(request.body, nullptr, false);
        if (body.is_discarded() || !body.contains("challenge") || !body.contains("blob")) {
            response.status = 400;
            respondJson(response, {{"error", "bad request"}});
            return;
        }
        try {
            const std::string userId = login_.verify(body.at("challenge").get<std::string>(),
                body.at("blob").get<std::string>(), nowSeconds());
            const std::string token = session_.issue(userId, nowSeconds());
            response.set_header(
                "Set-Cookie", "session=" + token + "; HttpOnly; SameSite=Strict; Path=/");
            respondJson(response, {{"ok", true}, {"userId", userId}});
        } catch (const std::exception&) {
            response.status = 401;
            respondJson(response, {{"error", "login failed"}});
        }
    });

    // The logged-in user, from the session cookie.
    http_->Get("/portal/me", [this](const httplib::Request& request, httplib::Response& response) {
        try {
            const std::string userId = session_.verify(cookieValue(request, "session"), nowSeconds());
            respondJson(response, {{"userId", userId}});
        } catch (const std::exception&) {
            response.status = 401;
            respondJson(response, {{"error", "not authenticated"}});
        }
    });
}

}  // namespace bazarish::service
