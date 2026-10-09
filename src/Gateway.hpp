// Bazarish project (c) 2026
#pragma once

#include <bazarish/GatewayProtocol.hpp>
#include "Sessions.hpp"
#include "Settings.hpp"

#include <bazarish/Auth.hpp>
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

class Gateway {
public:
    Gateway(Settings settings, i2p::Router& router);
    ~Gateway();
    Gateway(const Gateway&) = delete;
    Gateway& operator=(const Gateway&) = delete;

    int start();
    void stop();
    int port() const;

    std::size_t sockets() const;
    std::size_t rejoins() const { return rejoins_.load(); }
    std::size_t refusals() const { return refused_.load(); }
    std::size_t dials() const { return dials_.load(); }

private:
    http::Response notFound() const;
    bool admitted(const http::Request& request) const;
    http::Response decoy() const;
    http::Response health(const http::Request& request) const;
    void bindOps();

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
    void onStreamEnd(const std::shared_ptr<Session>& session, const Frame& frame);
    void onRawSend(const std::shared_ptr<Session>& session, const http::SocketPtr& socket,
        const Frame& frame);
    void fail(const http::SocketPtr& socket, std::uint32_t ref, Fault fault,
        const std::string& why);

    struct Connection {
        std::shared_ptr<Session> session;
        bool resumed = false;
        bool greeted = false;
        std::uint32_t flow = 0;
    };

    std::shared_ptr<Session> sessionFor(const http::Socket* socket) const;
    static http::SocketPtr outletFor(const Session& session, const StreamEntry& stream);
    static http::SocketPtr answerOn(const Session& session, const http::SocketPtr& asked);
    void replayDone(const std::shared_ptr<Session>& session);
    void afterReplay(const std::shared_ptr<Session>& session);
    http::SocketPtr laneFor(const Session& session, const Frame& frame) const;

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
    void orphan(const std::shared_ptr<StreamEntry>& entry);
    void retire(const std::shared_ptr<Session>& session);

    struct Local {
        std::weak_ptr<Session> session;
        std::weak_ptr<EndpointEntry> endpoint;
    };
    std::optional<DirectRoute> directFor(const std::string& host) const;
    std::shared_ptr<EndpointEntry> localFor(
        const std::string& host, std::shared_ptr<Session>& owner) const;
    bool meetLocally(const std::shared_ptr<Session>& session,
        const std::shared_ptr<EndpointEntry>& from, std::uint32_t stream,
        const std::shared_ptr<Session>& owner, const std::shared_ptr<EndpointEntry>& to,
        const http::SocketPtr& answerTo);
    void pump(const std::shared_ptr<Session>& session,
        const std::shared_ptr<StreamEntry>& entry);

    Settings settings_;
    i2p::Router& router_;
    http::Server server_;
    std::unique_ptr<http::Server> ops_;
    SessionStore sessions_;
    mutable std::mutex mutex_;
    mutable auth::ReplayCache operatorReplays_;
    std::map<const http::Socket*, Connection> connections_;
    std::map<std::string, Local> published_;
    std::thread status_;
    std::atomic<std::size_t> rejoins_{0};
    std::atomic<std::size_t> refused_{0};
    std::atomic<std::size_t> dials_{0};
    std::int64_t startedAt_ = 0;
    std::atomic<bool> running_{false};
};

}  // namespace bazarish::gateway
