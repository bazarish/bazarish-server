// Bazarish project (c) 2026
#include "PerUserDestinations.hpp"

#include "Federation.hpp"

#include <bazarish/Address.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/FederationFrame.hpp>
#include <bazarish/JsonRead.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/PrivateFile.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <exception>
#include <fstream>
#include <functional>
#include <iterator>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <utility>

namespace bazarish::server {

namespace {
constexpr int kPublishWaitSeconds = 180;
constexpr int kPublishPollSeconds = 1;
constexpr int kAcceptTimeoutSeconds = 2;
constexpr std::size_t kServeWorkers = 3;
constexpr int kServeDeadlineSeconds = 45;
constexpr int kWatchdogTickSeconds = 2;
constexpr int kEndpointPollMillis = 200;
constexpr std::chrono::minutes kExpirySweepInterval{10};

nlohmann::json readRecord(const std::filesystem::path& path)
{
    return bazarish::parseJson(bazarish::readFileText(path));
}

std::string addressOfTransient(const std::string& transientB64)
{
    try {
        return bazarish::i2p::routingHost(
            bazarish::i2p::Keys::fromBlob(fromBase64(transientB64)).publicBase64());
    } catch (const std::exception&) {
        return {};
    }
}

void requireUsableDelegation(
    const std::string& transientB64, const std::int64_t expiresUnix, const std::int64_t now)
{
    const bazarish::i2p::Keys keys = bazarish::i2p::Keys::fromBlob(fromBase64(transientB64));
    bazarish::i2p::requireUsableDelegation(keys, now);
    bazarish::i2p::requireDelegationEnds(keys, expiresUnix);
}

Key accountKey(const std::string& pem, const char* const what)
{
    try {
        return Key::fromPrivatePem(pem);
    } catch (const std::runtime_error& error) {
        throw std::invalid_argument(std::string(what) + " is not a private key: " + error.what());
    }
}

void requireServingKeys(const Key& sealing, const Key& signing)
{
    if (!sealing.hasPrivate() || !sealing.hasKem()) {
        throw std::invalid_argument("a serving key is a hybrid sealing key with its private half");
    }
    if (!signing.hasPrivate() || !signing.isA(kClassicalSigningAlgorithm)) {
        throw std::invalid_argument("a destination signs with a private Ed25519 key");
    }
}

void removeRecord(const std::filesystem::path& path, const std::string& userFp)
{
    std::error_code ec;
    std::filesystem::remove(path, ec);
    if (ec) {
        throw std::runtime_error("the destination record of " + bazarish::log::redact(userFp)
            + " cannot be removed: " + ec.message());
    }
}

SignAckFn signAckWith(std::shared_ptr<Key> signingKey)
{
    return [signingKey = std::move(signingKey)](const std::string& deliveryId,
               Bytes& outSignerPublicDer, Bytes& outSignature) {
        const Bytes signedBytes = deliveryAckInput(deliveryId);
        outSignature = bazarish::sign(*signingKey, signedBytes);
        outSignerPublicDer = signingKey->publicDer();
    };
}

}  // namespace

PerUserDestinations::PerUserDestinations(
    const std::optional<std::reference_wrapper<bazarish::i2p::Router>> router, DeliveryEngine& engine, std::filesystem::path stateDir, const bazarish::i2p::Privacy privacy,
    GetCardFn getCard, std::function<void()> servedChanged)
    : router_(router)
    , engine_(engine)
    , stateDir_(std::move(stateDir))
    , privacy_(privacy)
    , getCard_(std::move(getCard))
    , servedChanged_(std::move(servedChanged))
{
}

PerUserDestinations::~PerUserDestinations()
{
    stopGate_.stop();
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        sweepDue_.notify_all();
    }
    if (sweeper_.joinable()) {
        sweeper_.join();
    }
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> users;
        for (const auto& entry : dests_) {
            users.push_back(entry.first);
        }
        for (const std::string& user : users) {
            teardownLocked(user);
        }
    }
    {
        const std::lock_guard<std::mutex> lock(watchMutex_);
        for (const auto& entry : watched_) {
            if (const std::shared_ptr<bazarish::i2p::Stream> held = entry.first.lock()) {
                held->close();
            }
        }
    }
    reapRetired();
    if (watchdog_.joinable()) {
        watchdog_.join();
    }
}

void PerUserDestinations::reapRetired()
{
    std::vector<std::shared_ptr<Destination>> retired;
    {
        const std::lock_guard<std::mutex> lock(retiringMutex_);
        retired.swap(retiring_);
    }
    for (auto& destination : retired) {
        destination->running = false;
        for (std::thread& worker : destination->workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }
}

void PerUserDestinations::watchStream(const std::shared_ptr<bazarish::i2p::Stream>& stream)
{
    const std::lock_guard<std::mutex> lock(watchMutex_);
    watched_.emplace_back(stream,
        std::chrono::steady_clock::now() + std::chrono::seconds(kServeDeadlineSeconds));
}

void PerUserDestinations::unwatchStream(const std::shared_ptr<bazarish::i2p::Stream>& stream)
{
    const std::lock_guard<std::mutex> lock(watchMutex_);
    watched_.erase(std::remove_if(watched_.begin(), watched_.end(),
                       [&stream](const auto& entry) {
                           const std::shared_ptr<bazarish::i2p::Stream> held = entry.first.lock();
                           return !held || held == stream;
                       }),
        watched_.end());
}

void PerUserDestinations::startWatchdog()
{
    if (watchdog_.joinable()) {
        return;
    }
    watchdog_ = std::thread([this]() {
        while (!stopGate_.waitFor(std::chrono::seconds(kWatchdogTickSeconds))) {
            const std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
            const std::lock_guard<std::mutex> lock(watchMutex_);
            for (const auto& entry : watched_) {
                const std::shared_ptr<bazarish::i2p::Stream> held = entry.first.lock();
                if (held && entry.second <= now) {
                    held->close();
                }
            }
        }
    });
}

std::filesystem::path PerUserDestinations::destsDir() const
{
    return stateDir_ / "i2p-user-dests";
}

std::filesystem::path PerUserDestinations::pathFor(const std::string& userFp) const
{
    if (!bazarish::isFingerprint(userFp)) {
        throw std::invalid_argument("not a fingerprint: no destination record is named that");
    }
    return destsDir() / userFp;
}

void PerUserDestinations::bringUp(const std::string& userFp, const std::string& transientB64,
    const std::int64_t expiresUnix, const std::string& sealingKeyPem,
    const std::string& signingKeyPem)
{
    const auto dest = std::make_shared<Destination>();
    dest->transientB64 = transientB64;
    dest->expiresUnix = expiresUnix;
    dest->sealingKey = std::make_shared<Key>(Key::fromPrivatePem(sealingKeyPem));
    dest->signingKey = std::make_shared<Key>(Key::fromPrivatePem(signingKeyPem));
    dest->dest = addressOfTransient(transientB64);
    sweepDue_.notify_all();
    if (router_.has_value()) {
        for (std::size_t i = 1; i < kServeWorkers; ++i) {
            dest->workers.emplace_back([this, dest, userFp]() { serveLoop(*dest, userFp); });
        }
        dest->workers.emplace_back([this, dest, transientB64, userFp]() {
            try {
                const bazarish::i2p::Keys keys
                    = bazarish::i2p::Keys::fromBlob(fromBase64(transientB64));
                auto endpoint = router_->get().createEndpoint(bazarish::i2p::EndpointConfig{
                    keys, privacy_, bazarish::i2p::kServerTunnelQuantity, true});
                {
                    const std::lock_guard<std::mutex> lock(mutex_);
                    dest->endpoint = endpoint;
                }
                bool up = false;
                for (int waited = 0; waited < kPublishWaitSeconds && dest->running.load();
                     waited += kPublishPollSeconds) {
                    up = endpoint->waitReady(std::chrono::seconds(kPublishPollSeconds));
                    if (up) {
                        break;
                    }
                }
                if (!dest->running.load()) {
                    endpoint->stop();
                    return;
                }
                if (up) {
                    bazarish::log::info("per-user i2p destination up for {}",
                        bazarish::log::redact(userFp));
                } else {
                    bazarish::log::warn(
                        "per-user i2p destination for {} has no LeaseSet after {} s; the router "
                        "keeps building, the account is unreachable until it has one",
                        bazarish::log::redact(userFp), kPublishWaitSeconds);
                }
                serveLoop(*dest, userFp);
            } catch (const std::exception& error) {
                bazarish::log::warn("destination for {} is down: {}",
                    bazarish::log::redact(userFp), error.what());
            }
        });
    }
    dests_[userFp] = dest;
}

void PerUserDestinations::serveLoop(Destination& destination, const std::string& userFp)
{
    std::shared_ptr<bazarish::i2p::Endpoint> endpoint;
    while (destination.running.load() && !endpoint) {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            endpoint = destination.endpoint;
        }
        if (!endpoint) {
            std::this_thread::sleep_for(std::chrono::milliseconds(kEndpointPollMillis));
        }
    }
    if (!endpoint) {
        return;
    }
    while (destination.running.load()) {
        std::string peer;
        std::shared_ptr<bazarish::i2p::Stream> stream;
        try {
            stream = endpoint->accept(peer, std::chrono::seconds(kAcceptTimeoutSeconds));
        } catch (const std::exception& error) {
            // Over SAM the router refuses while another session still holds the address.
            bazarish::log::warn("a user's destination takes no streams yet: {}", error.what());
            std::this_thread::sleep_for(std::chrono::seconds(kAcceptTimeoutSeconds));
            continue;
        }
        if (!stream) {
            continue;
        }
        if (!destination.running.load()) {
            stream->close();
            return;
        }
        try {
            std::shared_ptr<Key> serving;
            std::shared_ptr<Key> signingKey;
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                serving = destination.sealingKey;
                signingKey = destination.signingKey;
            }
            watchStream(stream);
            federationServeOnce(*stream, engine_, nowSeconds(), peer, *serving, userFp,
                getCard_, signAckWith(signingKey));
            unwatchStream(stream);
        } catch (const std::exception& error) {
            unwatchStream(stream);
            bazarish::log::warn("serving a user's destination failed: {}", error.what());
        }
    }
}

void PerUserDestinations::teardownLocked(const std::string& userFp)
{
    const auto it = dests_.find(userFp);
    if (it == dests_.end()) {
        return;
    }
    it->second->running = false;
    if (it->second->endpoint) {
        it->second->endpoint->stop();
    }
    {
        const std::lock_guard<std::mutex> lock(retiringMutex_);
        retiring_.push_back(std::move(it->second));
    }
    dests_.erase(it);
}

PerUserDestinations::Assignment PerUserDestinations::provision(const std::string& userFp,
    const std::string& transientB64, const std::int64_t expiresUnix,
    const std::string& sealingKeyPem, const std::string& signingKeyPem)
{
    requireUsableDelegation(transientB64, expiresUnix, nowSeconds());
    const Key sealing = accountKey(sealingKeyPem, "the serving key");
    const Key signing = accountKey(signingKeyPem, "the signing key");
    requireServingKeys(sealing, signing);
    reapRetired();
    Assignment served;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto existing = dests_.find(userFp);
        if (existing != dests_.end() && existing->second->transientB64 == transientB64
            && existing->second->sealingKey->publicDer() == sealing.publicDer()
            && existing->second->signingKey->publicDer() == signing.publicDer()) {
            return assignedLocked(*existing->second, nowSeconds());
        }
        std::error_code ec;
        std::filesystem::create_directories(destsDir(), ec);
        const nlohmann::json record = {{"transient", transientB64},
            {"expiresUnix", expiresUnix}, {"sealingKey", sealingKeyPem},
            {"signingKey", signingKeyPem}};
        try {
            writePrivateFile(pathFor(userFp), record.dump());
        } catch (const std::exception& error) {
            throw std::runtime_error("cannot persist the destination record for "
                + bazarish::log::redact(userFp) + ": " + error.what());
        }
        teardownLocked(userFp);
        bringUp(userFp, transientB64, expiresUnix, sealingKeyPem, signingKeyPem);
        served = assignedLocked(*dests_.at(userFp), nowSeconds());
    }
    reapRetired();
    announceServed();
    return served;
}

std::size_t PerUserDestinations::sweepExpired(const std::int64_t now)
{
    std::vector<std::string> lapsed;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [userFp, dest] : dests_) {
            if (bazarish::i2p::delegationLapsed(dest->expiresUnix, now)) {
                lapsed.push_back(userFp);
            }
        }
        for (const std::string& userFp : lapsed) {
            try {
                removeRecord(pathFor(userFp), userFp);
            } catch (const std::exception& error) {
                bazarish::log::warn("lapsed destination record for {} not removed: {}",
                    bazarish::log::redact(userFp), error.what());
            }
            teardownLocked(userFp);
            bazarish::log::info("delegation for {} ran out: destination taken down",
                bazarish::log::redact(userFp));
        }
    }
    if (!lapsed.empty()) {
        announceServed();
    }
    return lapsed.size();
}

void PerUserDestinations::startSweeper()
{
    if (sweeper_.joinable()) {
        return;
    }
    startWatchdog();
    sweeper_ = std::thread([this]() {
        for (;;) {
            {
                std::unique_lock<std::mutex> lock(mutex_);
                if (stopGate_.stopped()) {
                    return;
                }
                sweepDue_.wait_for(lock, nextSweepInLocked(nowSeconds()));
                if (stopGate_.stopped()) {
                    return;
                }
            }
            reapRetired();
            try {
                sweepExpired(nowSeconds());
            } catch (const std::exception& error) {
                bazarish::log::warn("destination expiry sweep failed: {}", error.what());
            }
        }
    });
}

void PerUserDestinations::forget(const std::string& userFp)
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        removeRecord(pathFor(userFp), userFp);
        teardownLocked(userFp);
    }
    reapRetired();
    announceServed();
}

void PerUserDestinations::reloadPersisted(const std::int64_t now)
{
    startSweeper();
    reloadLocked(now);
    announceServed();
}

void PerUserDestinations::reloadLocked(const std::int64_t now)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    std::error_code ec;
    if (!std::filesystem::exists(destsDir(), ec)) {
        return;
    }
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
        try {
            const nlohmann::json record = readRecord(entry.path());
            const std::int64_t expiresUnix = record.at("expiresUnix").get<std::int64_t>();
            if (bazarish::i2p::delegationLapsed(expiresUnix, now)) {
                continue;
            }
            const std::string transientB64 = record.at("transient").get<std::string>();
            requireUsableDelegation(transientB64, expiresUnix, now);
            bringUp(entry.path().filename().string(), transientB64, expiresUnix,
                record.at("sealingKey").get<std::string>(),
                record.at("signingKey").get<std::string>());
        } catch (const std::exception& error) {
            bazarish::log::warn("destination record {} skipped at start: {}",
                bazarish::log::redact(entry.path().filename().string()), error.what());
        }
    }
}

void PerUserDestinations::announceServed() const
{
    if (servedChanged_) {
        servedChanged_();
    }
}

std::vector<std::string> PerUserDestinations::served() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> hosts;
    for (const auto& [userFp, destination] : dests_) {
        (void)userFp;
        if (!destination->dest.empty()) {
            hosts.push_back(destination->dest);
        }
    }
    return hosts;
}

bool PerUserDestinations::serveDirect(
    const std::string& to, const std::string& from, TlsPipe& pipe)
{
    std::string owner;
    std::shared_ptr<Key> sealing;
    std::shared_ptr<Key> signing;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [userFp, destination] : dests_) {
            if (destination->dest == to) {
                owner = userFp;
                sealing = destination->sealingKey;
                signing = destination->signingKey;
                break;
            }
        }
    }
    if (owner.empty()) {
        return false;
    }
    pipe.closeAfter(std::chrono::seconds(kServeDeadlineSeconds));
    federationServeOnce(pipe, engine_, nowSeconds(), from, *sealing, owner, getCard_,
        signAckWith(std::move(signing)));
    return true;
}

std::size_t PerUserDestinations::size() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return dests_.size();
}

PerUserDestinations::Assignment PerUserDestinations::assignmentFor(
    const std::string& userFp, const std::int64_t now) const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto found = dests_.find(userFp);
    if (found == dests_.end()) {
        return {};
    }
    return assignedLocked(*found->second, now);
}

std::chrono::seconds PerUserDestinations::nextSweepIn(const std::int64_t now) const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return nextSweepInLocked(now);
}

std::chrono::seconds PerUserDestinations::nextSweepInLocked(const std::int64_t now) const
{
    std::chrono::seconds due = kExpirySweepInterval;
    for (const auto& [userFp, dest] : dests_) {
        (void)userFp;
        if (dest->expiresUnix > 0) {
            const std::int64_t downAt
                = dest->expiresUnix - bazarish::i2p::kDelegationLapseLeadSeconds;
            due = std::min(due, std::chrono::seconds(std::max<std::int64_t>(0, downAt - now)));
        }
    }
    return due;
}

std::int64_t PerUserDestinations::heldUntil(const std::string& userFp) const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto found = dests_.find(userFp);
    return found == dests_.end() ? 0 : found->second->expiresUnix;
}

PerUserDestinations::Assignment PerUserDestinations::assignedLocked(
    const Destination& destination, const std::int64_t now)
{
    Assignment assignment;
    assignment.dest = destination.dest;
    assignment.sealingKey = destination.sealingKey;
    if (destination.expiresUnix != 0 && now >= destination.expiresUnix) {
        assignment.state = "expired";
    } else if (destination.dest.empty() || !destination.endpoint
        || !destination.endpoint->ready()) {
        assignment.state = "building";
    } else {
        assignment.state = "active";
    }
    return assignment;
}

}  // namespace bazarish::server
