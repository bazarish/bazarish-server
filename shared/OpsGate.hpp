// Bazarish project (c) 2026
#pragma once

#include <bazarish/Auth.hpp>
#include <bazarish/HttpServer.hpp>

#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::server {

using Refusal = std::function<std::optional<http::Response>(const http::Request&)>;

Refusal operatorCheck(const std::vector<std::string>& operators, auth::ReplayCache& replays);

// A body that does not read is answered 400.
http::Handler operatorOnly(
    const std::vector<std::string>& operators, auth::ReplayCache& replays, http::Handler handler);
http::Filler operatorOnly(
    const std::vector<std::string>& operators, auth::ReplayCache& replays, http::Filler handler);

}  // namespace bazarish::server
