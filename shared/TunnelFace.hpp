// Bazarish project (c) 2026
#pragma once

#include "SessionStore.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/HttpServer.hpp>

#include <memory>
#include <optional>
#include <string>

namespace bazarish::server {

struct Caller {
    std::string user;
    std::string device;
    DeviceRole role = DeviceRole::eSecondary;
    // Set when the request is not let in; the user is empty then.
    std::optional<http::Response> refused;
};

class TunnelFace {
public:
    explicit TunnelFace(std::shared_ptr<Key> sealingKey);

    void serve(const http::Request& request, http::Server& routes, http::Responder respond);

    Caller authenticate(const http::Request& request);

private:
    const std::shared_ptr<Key> sealingKey_;
    SessionStore sessions_;
    auth::ReplayCache replays_;
};

}  // namespace bazarish::server
