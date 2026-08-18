// Bazarish project (c) 2026
#include "PerUserDestinations.hpp"

#include "Federation.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/Log.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <ctime>
#include <exception>
#include <fstream>
#include <iterator>
#include <system_error>
#include <thread>
#include <utility>

namespace bazarish::server {

namespace {
// How long a fresh destination is given to get its LeaseSet published before the
// wait is called off. Not a deadline for the router: it keeps retrying on its own
// (i2pd re-publishes on a 1.8 s confirmation timer and re-verifies every 100 s),
// this only bounds how long the bring-up thread waits before saying so.
constexpr int kPublishWaitSeconds = 180;
// The wait is taken in short steps so a teardown that arrives meanwhile is seen
// at once: the operator push that triggers it has a client waiting on the answer.
constexpr int kPublishPollSeconds = 1;
// Likewise for the accept loop: this is how long a stopping destination can keep
// its caller waiting, not how long it waits for a peer.
constexpr int kAcceptTimeoutSeconds = 2;


std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

}  // namespace

PerUserDestinations::PerUserDestinations(bazarish::i2p::Router* const router,
    DeliveryEngine& engine, std::filesystem::path stateDir, const bazarish::i2p::Privacy privacy,
    const int tunnelQuantity, FederationRateLimiter* const limiter)
    : router_(router)
    , engine_(engine)
    , stateDir_(std::move(stateDir))
    , privacy_(privacy)
    , tunnelQuantity_(tunnelQuantity)
    , limiter_(limiter)
{
}

PerUserDestinations::~PerUserDestinations()
{
    const std::lock_guard<std::mutex> lock(mutex_);
    for (auto& entry : dests_) {
        entry.second->running = false;
    }
    for (auto& entry : dests_) {
        if (entry.second->worker.joinable()) {
            entry.second->worker.join();
        }
    }
}

std::filesystem::path PerUserDestinations::destsDir() const
{
    return stateDir_ / "i2p-user-dests";
}

std::filesystem::path PerUserDestinations::pathFor(const std::string& userFp) const
{
    return destsDir() / userFp;
}

void PerUserDestinations::bringUp(const std::string& userFp, const std::string& transientB64,
    const std::int64_t expiresUnix, const std::string& sealingKeyPem,
    const std::string& signingKeyPem)
{
    auto dest = std::make_unique<Destination>();
    dest->transientB64 = transientB64;
    dest->expiresUnix = expiresUnix;
    dest->sealingKey = std::make_shared<Key>(Key::fromPrivatePem(sealingKeyPem));
    dest->signingKey = std::make_shared<Key>(Key::fromPrivatePem(signingKeyPem));
    Destination* const raw = dest.get();
    // Without a router (tests / router-less mode) only the persisted/registered
    // state is kept; no destination is built, so it stays in "building".
    if (router_ != nullptr) {
        raw->worker = std::thread([this, raw, transientB64, userFp]() {
            try {
                // The transient is a base64-encoded i2pd private-keys blob with an
                // offline section; a STANDARD LeaseSet2 (offline-signature dests
                // cannot publish an encrypted one), so the address is the master b32.
                const bazarish::i2p::Keys keys = bazarish::i2p::Keys::fromBlob(fromBase64(transientB64));
                auto endpoint = router_->createEndpoint(bazarish::i2p::EndpointConfig{
                    keys, bazarish::i2p::LeaseSetKind::eStandard, privacy_, tunnelQuantity_, true});
                {
                    // Publish the resolved address for surfacing to the user and
                    // same-destination local delivery matching; keep the endpoint so
                    // outbound federation can dial from it.
                    const std::lock_guard<std::mutex> lock(mutex_);
                    raw->dest = endpoint->routingHost();
                    raw->endpoint = endpoint;
                }
                // The endpoint exists at once; being reachable means its LeaseSet is
                // published, which needs tunnels and a floodfill that answers. Say
                // which of the two has happened, and never the second for the first.
                bool published = false;
                for (int waited = 0; waited < kPublishWaitSeconds && raw->running.load();
                     waited += kPublishPollSeconds) {
                    published = endpoint->waitReady(std::chrono::seconds(kPublishPollSeconds));
                    if (published) {
                        break;
                    }
                }
                if (!raw->running.load()) {
                    return;  // torn down while its LeaseSet was still publishing
                }
                if (published) {
                    bazarish::log::info("per-user i2p destination published for {}",
                        bazarish::log::redact(userFp));
                } else {
                    bazarish::log::warn(
                        "per-user i2p destination for {} not published after {} s; the router "
                        "keeps retrying, the account is unreachable until it succeeds",
                        bazarish::log::redact(userFp), kPublishWaitSeconds);
                }
                while (raw->running.load()) {
                    std::string peer;
                    auto stream = endpoint->accept(peer, std::chrono::seconds(kAcceptTimeoutSeconds));
                    if (!stream) {
                        continue;  // accept timeout / stop
                    }
                    try {
                        const std::string sender = peer;
                        federationServeOnce(*stream, engine_, nowSeconds(), peer, limiter_,
                            raw->sealingKey.get(), getCard_,
                            // Ack a stored delivery from THIS per-user dest back to
                            // the sender's serving dest.
                            [this, endpoint, sender, signingKey = raw->signingKey](
                                const std::string& messageId) {
                                if (!ackSender_) {
                                    return;
                                }
                                // Send the delivered-ack on a detached thread: it
                                // dials a fresh outbound connection back to the
                                // sender, which must never block this destination's
                                // single accept loop (a slow dial would stall every
                                // later inbound delivery). Captures own copies (the
                                // ack function and the shared endpoint/key), so it is
                                // safe if this destination is torn down while the ack
                                // is still in flight.
                                std::thread([ackSender = ackSender_, endpoint, sender,
                                                messageId, signingKey]() {
                                    // No accept-loop try/catch wraps a detached
                                    // thread - an escaping exception would terminate
                                    // the process, so contain it here (a failed ack is
                                    // best-effort; the sender retries on its own).
                                    try {
                                        ackSender(*endpoint, sender, messageId, *signingKey);
                                    } catch (const std::exception& error) {
                                        bazarish::log::warn(
                                            "ack to sender failed: {}", error.what());
                                    }
                                }).detach();
                            },
                            // A delivered-ack landing here (we sent from this dest)
                            // marks our local attempt delivered.
                            [this](const std::string& messageId) {
                                if (onAck_) {
                                    onAck_(messageId);
                                }
                            });
                    } catch (const std::exception& error) {
                        // A failed serve must not kill the loop.
                        bazarish::log::warn("serving a user's destination failed: {}",
                            error.what());
                    }
                }
            } catch (const std::exception& error) {
                // Bad/expired transient: the destination stays down until the next
                // provision, and the user cannot be reached until then.
                bazarish::log::warn("destination for {} is down: {}",
                    bazarish::log::redact(userFp), error.what());
            }
        });
    }
    dests_[userFp] = std::move(dest);
}

void PerUserDestinations::teardownLocked(const std::string& userFp)
{
    const auto it = dests_.find(userFp);
    if (it == dests_.end()) {
        return;
    }
    it->second->running = false;
    if (it->second->worker.joinable()) {
        it->second->worker.join();
    }
    dests_.erase(it);
}

void PerUserDestinations::provision(const std::string& userFp, const std::string& transientB64,
    const std::int64_t expiresUnix)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto existing = dests_.find(userFp);
    if (existing != dests_.end() && existing->second->transientB64 == transientB64) {
        return;  // already serving this exact transient
    }
    // Reuse a previously-issued serving sealing key and federation signing key
    // (from the running destination, else the persisted record) so the user's
    // contact card and signer stay stable across renewals; mint fresh ones only
    // for a brand-new destination.
    std::string sealingKeyPem;
    std::string signingKeyPem;
    if (existing != dests_.end() && existing->second->sealingKey) {
        sealingKeyPem = existing->second->sealingKey->privatePem();
    }
    if (existing != dests_.end() && existing->second->signingKey) {
        signingKeyPem = existing->second->signingKey->privatePem();
    }
    if (sealingKeyPem.empty() || signingKeyPem.empty()) {
        std::ifstream in(pathFor(userFp), std::ios::binary);
        const std::string text(
            (std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        if (!text.empty()) {
            try {
                const nlohmann::json record = nlohmann::json::parse(text);
                if (sealingKeyPem.empty() && record.contains("sealingKey")) {
                    sealingKeyPem = record.at("sealingKey").get<std::string>();
                }
                if (signingKeyPem.empty() && record.contains("signingKey")) {
                    signingKeyPem = record.at("signingKey").get<std::string>();
                }
            } catch (const std::exception& error) {
                // Malformed record: fall through to minting fresh keys. That changes
                // the user's serving key, so it must not happen quietly.
                bazarish::log::warn("destination record for {} unreadable, minting fresh keys: {}",
                    bazarish::log::redact(userFp), error.what());
            }
        }
    }
    if (sealingKeyPem.empty()) {
        sealingKeyPem = Key::generateSealing().privatePem();
    }
    if (signingKeyPem.empty()) {
        signingKeyPem = Key::generateSigning().privatePem();
    }
    // Persist first so a restart re-provisions even if the bring-up below races.
    std::error_code ec;
    std::filesystem::create_directories(destsDir(), ec);
    const nlohmann::json record = {{"transient", transientB64}, {"expiresUnix", expiresUnix},
        {"sealingKey", sealingKeyPem}, {"signingKey", signingKeyPem}};
    const std::string text = record.dump();
    {
        std::ofstream out(pathFor(userFp), std::ios::binary | std::ios::trunc);
        out.write(text.data(), static_cast<std::streamsize>(text.size()));
        out.close();
        if (!out) {
            // This record is the destination: unwritten, the address is up now and
            // gone at the next start, with the user unreachable and nothing said.
            throw std::runtime_error("cannot persist the destination record for "
                + bazarish::log::redact(userFp));
        }
    }
    teardownLocked(userFp);
    bringUp(userFp, transientB64, expiresUnix, sealingKeyPem, signingKeyPem);
}

void PerUserDestinations::revoke(const std::string& userFp)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    std::error_code ec;
    std::filesystem::remove(pathFor(userFp), ec);
    if (ec) {
        // The record outliving the revoke means the destination comes back at the
        // next start: a revoke that did not stick must not look like one that did.
        bazarish::log::warn("revoked destination record for {} not removed: {}",
            bazarish::log::redact(userFp), ec.message());
    }
    teardownLocked(userFp);
}

void PerUserDestinations::reloadPersisted(const std::int64_t now)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    std::error_code ec;
    if (!std::filesystem::exists(destsDir(), ec)) {
        return;
    }
    // An unreadable directory would otherwise mean "no destinations to bring up",
    // which is indistinguishable from a node that has none.
    std::filesystem::directory_iterator dests(destsDir(), ec);
    if (ec) {
        bazarish::log::warn("no destinations reloaded, {} unreadable: {}", destsDir().string(),
            ec.message());
        return;
    }
    for (const auto& entry : dests) {
        if (!entry.is_regular_file()) {
            continue;
        }
        std::ifstream in(entry.path(), std::ios::binary);
        const std::string text(
            (std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        try {
            const nlohmann::json record = nlohmann::json::parse(text);
            const std::int64_t expiresUnix = record.at("expiresUnix").get<std::int64_t>();
            if (expiresUnix <= now) {
                continue;  // the offline transient has already expired
            }
            const std::string transientB64 = record.at("transient").get<std::string>();
            // Reuse the persisted serving and signing keys (older records may
            // predate either; mint a missing one).
            const std::string sealingKeyPem = record.contains("sealingKey")
                ? record.at("sealingKey").get<std::string>()
                : Key::generateSealing().privatePem();
            const std::string signingKeyPem = record.contains("signingKey")
                ? record.at("signingKey").get<std::string>()
                : Key::generateSigning().privatePem();
            bringUp(entry.path().filename().string(), transientB64, expiresUnix, sealingKeyPem,
                signingKeyPem);
        } catch (const std::exception& error) {
            // Skip a malformed record rather than fail startup - that user's
            // destination stays down, which the operator has to be able to see.
            bazarish::log::warn("destination record {} skipped at start: {}",
                entry.path().filename().string(), error.what());
        }
    }
}

void PerUserDestinations::setGetCard(GetCardFn getCard)
{
    getCard_ = std::move(getCard);
}

void PerUserDestinations::setAckSender(AckSenderFn ackSender)
{
    ackSender_ = std::move(ackSender);
}

void PerUserDestinations::setOnAck(OnAckFn onAck)
{
    onAck_ = std::move(onAck);
}

std::shared_ptr<bazarish::i2p::Endpoint> PerUserDestinations::endpointForDest(
    const std::string& dest) const
{
    if (dest.empty()) {
        return nullptr;
    }
    const std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [user, d] : dests_) {
        (void)user;
        if (d->dest == dest) {
            return d->endpoint;
        }
    }
    return nullptr;
}

std::size_t PerUserDestinations::size() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return dests_.size();
}

std::shared_ptr<Key> PerUserDestinations::servingKeyFor(const std::string& userFp) const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto it = dests_.find(userFp);
    if (it == dests_.end()) {
        return nullptr;
    }
    return it->second->sealingKey;
}

std::string PerUserDestinations::destinationFor(const std::string& userFp) const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto it = dests_.find(userFp);
    if (it == dests_.end()) {
        return std::string();
    }
    return it->second->dest;
}

std::string PerUserDestinations::stateFor(const std::string& userFp, const std::int64_t now) const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto it = dests_.find(userFp);
    if (it == dests_.end()) {
        return std::string();
    }
    if (it->second->expiresUnix != 0 && now >= it->second->expiresUnix) {
        return "expired";
    }
    if (it->second->dest.empty()) {
        return "building";
    }
    // "active" means reachable, so it follows the LeaseSet, not the object: an
    // endpoint whose publish has not landed yet is still building.
    const std::shared_ptr<bazarish::i2p::Endpoint> endpoint = it->second->endpoint;
    return (endpoint && endpoint->ready()) ? "active" : "building";
}

}  // namespace bazarish::server
