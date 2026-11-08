// Bazarish project (c) 2026
#include "WebFace.hpp"

#include <bazarish/WebAssets.hpp>

namespace bazarish::server {

namespace {

constexpr int kSeeOther = 303;

}  // namespace

void sendHtml(http::Response& response, const std::string& html, const int status)
{
    response.status = status;
    response.contentType = "text/html; charset=utf-8";
    response.headers["Cache-Control"] = "no-store";
    response.body = html;
}

void sendJson(http::Response& response, const nlohmann::json& body, const int status)
{
    sendJsonText(response, body.dump(), status);
}

void sendJsonText(http::Response& response, const std::string& text, const int status)
{
    response.status = status;
    response.contentType = "application/json";
    response.headers["Cache-Control"] = "no-store";
    response.body = text;
}

void redirectTo(http::Response& response, const std::string& location)
{
    response.status = kSeeOther;
    response.headers["Location"] = location;
}

void setCookie(http::Response& response, const std::string& name, const std::string& value,
    const std::string& attributes)
{
    response.headers["Set-Cookie"] = name + "=" + value + attributes;
}

void clearCookie(http::Response& response, const std::string& name, const std::string& attributes)
{
    response.headers["Set-Cookie"] = name + "=" + attributes + "; Max-Age=0";
}

std::string notice(const std::string& text, const std::string& kind)
{
    if (text.empty()) {
        return {};
    }
    return "<p class=\"notice " + kind + "\">" + htmlEscape(text) + "</p>";
}

}  // namespace bazarish::server
