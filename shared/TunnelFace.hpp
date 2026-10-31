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

class TunnelFace {
public:
    explicit TunnelFace(std::shared_ptr<Key> sealingKey);

    void serve(const http::Request& request, http::Server& routes, http::Responder respond);

    std::optional<http::Response> authenticate(const http::Request& request, std::string* outUser);

private:
    const std::shared_ptr<Key> sealingKey_;
    SessionStore sessions_;
    auth::ReplayCache replays_;
};

}  // namespace bazarish::server
