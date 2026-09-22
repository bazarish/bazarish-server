// Bazarish project (c) 2026
#pragma once

#include "Protocol.hpp"
#include "Sessions.hpp"
#include "Settings.hpp"

#include <bazarish/HttpServer.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/WebSocket.hpp>

#include <map>
#include <memory>
#include <mutex>
#include <string>

namespace bazarish::gateway {

// The daemon. It owns the listener, the sessions and the router the clients
// borrow, and it answers everything that is not a client with the same 404 as
// everything else on the host.
class Gateway {
public:
    Gateway(Settings settings, i2p::Router& router);
    ~Gateway();
    Gateway(const Gateway&) = delete;
    Gateway& operator=(const Gateway&) = delete;

    // Binds and serves; returns the bound port.
    int start();
    void stop();
    int port() const;

    // The one answer to everything that is not for this gateway, and to
    // everything for it that arrived without the token.
    http::Response notFound() const;

private:
    // True only for a request at the secret path carrying the right token. The
    // token is compared in constant time, because it is the secret that varies
    // between two requests to the same path.
    bool admitted(const http::Request& request) const;
    http::Response decoy() const;

    void socketOpened(const http::SocketPtr& socket, const http::Request& request);
    void socketMessage(const http::SocketPtr& socket, const std::vector<unsigned char>& message);
    void socketClosed(const http::SocketPtr& socket);

    void onFrame(const http::SocketPtr& socket, const Frame& frame);
    void onHello(const http::SocketPtr& socket, const Frame& frame);
    void fail(const http::SocketPtr& socket, std::uint32_t ref, Fault fault,
        const std::string& why);

    // What one socket belongs to.
    struct Connection {
        std::shared_ptr<Session> session;
        bool resumed = false;
        bool greeted = false;
    };

    Settings settings_;
    i2p::Router& router_;
    http::Server server_;
    SessionStore sessions_;
    mutable std::mutex mutex_;
    std::map<const http::Socket*, Connection> connections_;
};

}  // namespace bazarish::gateway
