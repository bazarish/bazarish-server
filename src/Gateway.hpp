// Bazarish project (c) 2026
#pragma once

#include <bazarish/GatewayProtocol.hpp>
#include "Sessions.hpp"
#include "Settings.hpp"

#include <bazarish/HttpServer.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/WebSocket.hpp>

#include <atomic>
#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
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
    void onAttach(const http::SocketPtr& socket, const Frame& frame);
    void onEndpointCreate(const std::shared_ptr<Session>& session,
        const http::SocketPtr& socket, const Frame& frame);
    void onEndpointStop(const std::shared_ptr<Session>& session, const http::SocketPtr& socket,
        const Frame& frame);
    void onStreamOpen(const std::shared_ptr<Session>& session, const http::SocketPtr& socket,
        const Frame& frame);
    void onStreamData(const std::shared_ptr<Session>& session, const http::SocketPtr& socket,
        const Frame& frame);
    void onStreamCredit(const std::shared_ptr<Session>& session, const http::SocketPtr& socket,
        const Frame& frame);
    void onStreamEnd(const std::shared_ptr<Session>& session, const http::SocketPtr& socket,
        const Frame& frame);
    void onRawSend(const std::shared_ptr<Session>& session, const http::SocketPtr& socket,
        const Frame& frame);
    void fail(const http::SocketPtr& socket, std::uint32_t ref, Fault fault,
        const std::string& why);

    // What one socket belongs to.
    struct Connection {
        std::shared_ptr<Session> session;
        bool resumed = false;
        bool greeted = false;
        // The flow this socket carries, when it carries one rather than the
        // session's control.
        std::uint32_t flow = 0;
    };

    std::shared_ptr<Session> sessionFor(const http::Socket* socket) const;
    // Where a flow's frames go: its own socket when one is attached, the
    // session's control socket otherwise.
    static http::SocketPtr outlet(const Session& session, const http::SocketPtr& own);

    // Accepting callers and waiting for datagrams both block, so both are a
    // thread of their own.
    void acceptLoop(const std::shared_ptr<Session>& session,
        const std::shared_ptr<EndpointEntry>& entry);
    void datagramLoop(const std::shared_ptr<Session>& session,
        const std::shared_ptr<EndpointEntry>& entry);
    void readLoop(const std::shared_ptr<Session>& session,
        const std::shared_ptr<StreamEntry>& entry);
    void dial(const std::shared_ptr<Session>& session,
        const std::shared_ptr<EndpointEntry>& from, std::uint32_t stream, std::string host,
        std::chrono::seconds deadline, const http::SocketPtr& answerTo);
    void statusLoop();
    void teardown(const std::shared_ptr<Session>& session,
        const std::shared_ptr<StreamEntry>& entry, Fault fault);

    // Every published destination this gateway operates, by the host peers
    // route to. A dial that lands in here is two of its own clients, and there
    // is nothing for I2P to carry.
    struct Local {
        std::weak_ptr<Session> session;
        std::weak_ptr<EndpointEntry> endpoint;
    };
    std::shared_ptr<EndpointEntry> localFor(
        const std::string& host, std::shared_ptr<Session>& owner) const;

    Settings settings_;
    i2p::Router& router_;
    http::Server server_;
    SessionStore sessions_;
    mutable std::mutex mutex_;
    std::map<const http::Socket*, Connection> connections_;
    std::map<std::string, Local> published_;
    std::thread status_;
    std::atomic<bool> running_{false};
};

}  // namespace bazarish::gateway
