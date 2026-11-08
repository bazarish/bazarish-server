// Bazarish project (c) 2026
#pragma once

#include <bazarish/HttpServer.hpp>

#include <nlohmann/json.hpp>

#include <string>

namespace bazarish::server {

inline constexpr int kHttpOk = 200;

// What a web face answers is never kept by a cache: every page shows a signed-in state.
void sendHtml(http::Response& response, const std::string& html, int status = kHttpOk);
void sendJson(http::Response& response, const nlohmann::json& body, int status = kHttpOk);
// A document another service wrote, passed on as it came.
void sendJsonText(http::Response& response, const std::string& text, int status = kHttpOk);
void redirectTo(http::Response& response, const std::string& location);
void setCookie(http::Response& response, const std::string& name, const std::string& value,
    const std::string& attributes);
void clearCookie(http::Response& response, const std::string& name, const std::string& attributes);
// A line of text in a page's notice box; nothing when there is no text.
std::string notice(const std::string& text, const std::string& kind);

}  // namespace bazarish::server
