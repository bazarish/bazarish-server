// Bazarish project (c) 2026
#pragma once

#include <bazarish/Auth.hpp>
#include <bazarish/HttpServer.hpp>

#include <string>
#include <vector>

namespace bazarish::server {

// A body that does not read is answered 400.
http::Handler operatorOnly(
    const std::vector<std::string>& operators, auth::ReplayCache& replays, http::Handler handler);
http::Filler operatorOnly(
    const std::vector<std::string>& operators, auth::ReplayCache& replays, http::Filler handler);

}  // namespace bazarish::server
