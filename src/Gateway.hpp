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


    // How many sockets this gateway is holding, across every session: one per
    // session's control, plus one for each flow that has a lane of its own.
    std::size_t sockets() const;
    // How many times a client has come back to a session it already had. A
    // client replaces its control socket on purpose, so this counts the churn
    // rather than any kind of trouble.
    std::size_t rejoins() const { return rejoins_.load(); }
    // How many frames this gateway has refused. A client that is speaking the
    // protocol produces none, so a test that sees one has found something its
    // own assertions did not.
    std::size_t refusals() const { return refused_.load(); }

private:
    // The one answer to everything that is not for this gateway, and to
    // everything for it that arrived without the token.
    http::Response notFound() const;
    // True only for a request at the secret path carrying the right token. The
    // token is compared in constant time, because it is the secret that varies
    // between two requests to the same path.
    bool admitted(const http::Request& request) const;
    http::Response decoy() const;
    // The health report the admin panel reads. It lives behind the same secret
    // path and the same token as everything else here: a well-known path would
    // tell a scan that this host runs a gateway.
    http::Response health(const http::Request& request) const;
    std::string healthPath() const;

    void socketOpened(const http::SocketPtr& socket, const http::Request& request);
    void socketMessage(const http::SocketPtr& socket, const std::vector<unsigned char>& message);
    void socketClosed(const http::SocketPtr& socket);

    void onFrame(const http::SocketPtr& socket, const Frame& frame);
    void onHello(const http::SocketPtr& socket, const Frame& frame);
    void onAttach(const http::SocketPtr& socket, const Frame& frame);
    void onResume(const std::shared_ptr<Session>& session, const http::SocketPtr& socket,
        const Frame& frame);
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
    // A stream's own socket, else its destination's, else the session's
    // control. A destination raised for one transfer has a socket of its own,
    // and everything on it rides that.
    static http::SocketPtr outletFor(const Session& session, const StreamEntry& stream);
    // The control socket has said what it owed (or nothing was owed): what
    // waited for its replay goes out now.
    void replayDone(const std::shared_ptr<Session>& session);
    // Which socket a data frame was supposed to arrive on, or none when the
    // frame is not one or names nothing.
    http::SocketPtr laneFor(const Session& session, const Frame& frame) const;

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
    // Tells the other half of a pair that this one has gone. Without it the
    // survivor waits for bytes from a stream that no longer exists.
    void orphan(const std::shared_ptr<StreamEntry>& entry);
    // Stops everything a session holds. A worker thread holds its session
    // alive, so a session nobody sweeps properly is a session that runs for
    // ever.
    void retire(const std::shared_ptr<Session>& session);

    // Every published destination this gateway operates, by the host peers
    // route to. A dial that lands in here is two of its own clients, and there
    // is nothing for I2P to carry.
    struct Local {
        std::weak_ptr<Session> session;
        std::weak_ptr<EndpointEntry> endpoint;
    };
    std::shared_ptr<EndpointEntry> localFor(
        const std::string& host, std::shared_ptr<Session>& owner) const;
    // Joins two of this gateway's own clients, so their bytes never leave the
    // process. Answers the dialler and tells the other side it has a caller.
    bool meetLocally(const std::shared_ptr<Session>& session,
        const std::shared_ptr<EndpointEntry>& from, std::uint32_t stream,
        const std::shared_ptr<Session>& owner, const std::shared_ptr<EndpointEntry>& to,
        const http::SocketPtr& answerTo);
    // Moves what is waiting into this side's client as far as its window
    // allows, and credits the other side for what actually left.
    void pump(const std::shared_ptr<Session>& session,
        const std::shared_ptr<StreamEntry>& entry);

    Settings settings_;
    i2p::Router& router_;
    SessionStore sessions_;
    http::Server server_;
    mutable std::mutex mutex_;
    std::map<const http::Socket*, Connection> connections_;
    std::map<std::string, Local> published_;
    std::thread status_;
    std::atomic<std::size_t> rejoins_{0};
    std::atomic<std::size_t> refused_{0};
    std::int64_t startedAt_ = 0;
    std::atomic<bool> running_{false};
};

}  // namespace bazarish::gateway
