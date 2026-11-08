// Bazarish project (c) 2026
#include "OpsGate.hpp"

#include <bazarish/Clock.hpp>
#include <bazarish/HttpResponses.hpp>

#include <nlohmann/json.hpp>

#include <optional>
#include <stdexcept>
#include <utility>

namespace bazarish::server {

namespace {

constexpr int kBadRequest = 400;

}  // namespace

http::Handler operatorOnly(
    const std::vector<std::string>& operators, auth::ReplayCache& replays, http::Handler handler)
{
    return [&operators, &replays, handler = std::move(handler)](
               const http::Request& request) -> http::Response {
        if (const std::optional<http::Response> refused
            = http::operatorRefusal(request, nowSeconds(), operators, replays);
            refused.has_value()) {
            return *refused;
        }
        try {
            return handler(request);
        } catch (const nlohmann::json::exception& error) {
            return http::errorResponse(kBadRequest, ErrorCode::eRequestFailed, error.what());
        } catch (const std::invalid_argument& error) {
            return http::errorResponse(kBadRequest, ErrorCode::eRequestFailed, error.what());
        }
    };
}

http::Filler operatorOnly(
    const std::vector<std::string>& operators, auth::ReplayCache& replays, http::Filler handler)
{
    return [&operators, &replays, handler = std::move(handler)](
               const http::Request& request, http::Response& response) {
        if (const std::optional<http::Response> refused
            = http::operatorRefusal(request, nowSeconds(), operators, replays);
            refused.has_value()) {
            response = *refused;
            return;
        }
        try {
            handler(request, response);
        } catch (const nlohmann::json::exception& error) {
            response = http::errorResponse(kBadRequest, ErrorCode::eRequestFailed, error.what());
        } catch (const std::invalid_argument& error) {
            response = http::errorResponse(kBadRequest, ErrorCode::eRequestFailed, error.what());
        }
    };
}

}  // namespace bazarish::server
