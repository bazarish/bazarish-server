// Bazarish project (c) 2026
#include "PerUserDestinations.hpp"

#include "Federation.hpp"

#include <bazarish/Address.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/I2pAddress.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/PrivateFile.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <exception>
#include <fstream>
#include <functional>
#include <iterator>
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
    std::ifstream in(path, std::ios::binary);
    const std::string text(
        (std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (text.empty()) {
        return nlohmann::json::object();
    }
    return nlohmann::json::parse(text);
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

std::string recordedAddress(const std::filesystem::path& path)
{
    try {
        return readRecord(path).value("address", std::string());
    } catch (const std::exception&) {
        return {};
    }
}

void requireUsableDelegation(const std::string& transientB64, const std::int64_t expiresUnix)
{
    const bazarish::i2p::Keys keys = bazarish::i2p::Keys::fromBlob(fromBase64(transientB64));
    if (!keys.isOffline()) {
        throw std::runtime_error("delegation carries the destination's own signing key");
    }
    if (keys.b33OfflineKeyDays() < 1) {
        throw std::runtime_error("delegation carries no b33 offline keys");
    }
    const std::int64_t expires = keys.transientExpires();
    if (expires != expiresUnix) {
        throw std::runtime_error("delegation runs out at " + std::to_string(expires)
            + ", not at the declared " + std::to_string(expiresUnix));
    }
}

}  // namespace

PerUserDestinations::PerUserDestinations(bazarish::i2p::Router* const router,
    DeliveryEngine& engine, std::filesystem::path stateDir, const bazarish::i2p::Privacy privacy,
    const int tunnelQuantity)
    : router_(router)
    , engine_(engine)
    , stateDir_(std::move(stateDir))
    , privacy_(privacy)
    , tunnelQuantity_(tunnelQuantity)
{
}

PerUserDestinations::~PerUserDestinations()
{
    stopGate_.stop();
    if (sweeper_.joinable()) {
        sweeper_.join();
    }
    if (watchdog_.joinable()) {
        watchdog_.join();
    }
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (auto& entry : dests_) {
            entry.second->running = false;
        }
        const std::lock_guard<std::mutex> retiringLock(retiringMutex_);
        for (auto& entry : dests_) {
            retiring_.push_back(std::move(entry.second));
        }
        dests_.clear();
    }
    reapRetired();
}

void PerUserDestinations::reapRetired()
{
    std::vector<std::unique_ptr<Destination>> retired;
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

void PerUserDestinations::unwatchStream(const bazarish::i2p::Stream* const stream)
{
    const std::lock_guard<std::mutex> lock(watchMutex_);
    watched_.erase(std::remove_if(watched_.begin(), watched_.end(),
                       [stream](const auto& entry) {
                           const std::shared_ptr<bazarish::i2p::Stream> held = entry.first.lock();
                           return !held || held.get() == stream;
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
    auto dest = std::make_unique<Destination>();
    dest->transientB64 = transientB64;
    dest->expiresUnix = expiresUnix;
    dest->sealingKey = std::make_shared<Key>(Key::fromPrivatePem(sealingKeyPem));
    dest->signingKey = std::make_shared<Key>(Key::fromPrivatePem(signingKeyPem));
    dest->dest = addressOfTransient(transientB64);
    Destination* const raw = dest.get();
    if (router_ != nullptr) {
        for (std::size_t i = 1; i < kServeWorkers; ++i) {
            raw->workers.emplace_back([this, raw, userFp]() { serveLoop(raw, userFp); });
        }
        raw->workers.emplace_back([this, raw, transientB64, userFp]() {
            try {
                const bazarish::i2p::Keys keys
                    = bazarish::i2p::Keys::fromBlob(fromBase64(transientB64));
                auto endpoint = router_->createEndpoint(bazarish::i2p::EndpointConfig{
                    keys, privacy_, tunnelQuantity_, true});
                {
                    const std::lock_guard<std::mutex> lock(mutex_);
                    raw->endpoint = endpoint;
                }
                bool up = false;
                for (int waited = 0; waited < kPublishWaitSeconds && raw->running.load();
                     waited += kPublishPollSeconds) {
                    up = endpoint->waitReady(std::chrono::seconds(kPublishPollSeconds));
                    if (up) {
                        break;
                    }
                }
                if (!raw->running.load()) {
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
                serveLoop(raw, userFp);
            } catch (const std::exception& error) {
                bazarish::log::warn("destination for {} is down: {}",
                    bazarish::log::redact(userFp), error.what());
            }
        });
    }
    dests_[userFp] = std::move(dest);
}

void PerUserDestinations::serveLoop(Destination* const raw, const std::string& userFp)
{
    std::shared_ptr<bazarish::i2p::Endpoint> endpoint;
    while (raw->running.load() && !endpoint) {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            endpoint = raw->endpoint;
        }
        if (!endpoint) {
            std::this_thread::sleep_for(std::chrono::milliseconds(kEndpointPollMillis));
        }
    }
    if (!endpoint) {
        return;
    }
    while (raw->running.load()) {
        std::string peer;
        const std::shared_ptr<bazarish::i2p::Stream> stream
            = endpoint->accept(peer, std::chrono::seconds(kAcceptTimeoutSeconds));
        if (!stream) {
            continue;
        }
        if (!raw->running.load()) {
            stream->close();
            return;
        }
        try {
            std::shared_ptr<Key> serving;
            std::shared_ptr<Key> signingKey;
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                serving = raw->sealingKey;
                signingKey = raw->signingKey;
            }
            watchStream(stream);
            federationServeOnce(*stream, engine_, nowSeconds(), peer, serving.get(),
                userFp, getCard_,
                [signingKey](const std::string& deliveryId, Bytes& outSignerPublicDer,
                    Bytes& outSignature) {
                    if (!signingKey) {
                        return;
                    }
                    const Bytes signedBytes(deliveryId.begin(), deliveryId.end());
                    outSignature = bazarish::sign(*signingKey, signedBytes);
                    outSignerPublicDer = signingKey->publicDer();
                });
            unwatchStream(stream.get());
        } catch (const std::exception& error) {
            unwatchStream(stream.get());
            // A failed serve must not kill the loop.
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
    const std::string& transientB64, const std::int64_t expiresUnix)
{
    requireUsableDelegation(transientB64, expiresUnix);
    reapRetired();
    Assignment served;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto existing = dests_.find(userFp);
        if (existing != dests_.end() && existing->second->transientB64 == transientB64) {
            return assignedLocked(*existing->second, nowSeconds());
        }
        const std::string address = addressOfTransient(transientB64);
        const bool sameAddress = !address.empty()
            && ((existing != dests_.end()
                    && addressOfTransient(existing->second->transientB64) == address)
                || recordedAddress(pathFor(userFp)) == address);

        std::string sealingKeyPem;
        std::string signingKeyPem;
        if (sameAddress && existing != dests_.end() && existing->second->sealingKey) {
            sealingKeyPem = existing->second->sealingKey->privatePem();
        }
        if (sameAddress && existing != dests_.end() && existing->second->signingKey) {
            signingKeyPem = existing->second->signingKey->privatePem();
        }
        if (sameAddress && (sealingKeyPem.empty() || signingKeyPem.empty())) {
            try {
                const nlohmann::json record = readRecord(pathFor(userFp));
                if (sealingKeyPem.empty()) {
                    sealingKeyPem = record.value("sealingKey", std::string());
                }
                if (signingKeyPem.empty()) {
                    signingKeyPem = record.value("signingKey", std::string());
                }
            } catch (const std::exception& error) {
                bazarish::log::warn("destination record for {} unreadable, minting fresh keys: {}",
                    bazarish::log::redact(userFp), error.what());
            }
        }
        if (sealingKeyPem.empty()) {
            sealingKeyPem = Key::generateSealing().privatePem();
        }
        if (signingKeyPem.empty()) {
            signingKeyPem = Key::generateSigning().privatePem();
        }
        std::error_code ec;
        std::filesystem::create_directories(destsDir(), ec);
        const nlohmann::json record = {{"transient", transientB64},
            {"expiresUnix", expiresUnix}, {"address", address},
            {"sealingKey", sealingKeyPem}, {"signingKey", signingKeyPem}};
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
    return served;
}

std::size_t PerUserDestinations::sweepExpired(const std::int64_t now)
{
    std::vector<std::string> lapsed;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [userFp, dest] : dests_) {
            if (dest->expiresUnix > 0 && dest->expiresUnix <= now) {
                lapsed.push_back(userFp);
            }
        }
        for (const std::string& userFp : lapsed) {
            std::error_code ec;
            std::filesystem::remove(pathFor(userFp), ec);
            if (ec) {
                bazarish::log::warn("lapsed destination record for {} not removed: {}",
                    bazarish::log::redact(userFp), ec.message());
            }
            teardownLocked(userFp);
            bazarish::log::info("delegation for {} ran out: destination taken down",
                bazarish::log::redact(userFp));
        }
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
        while (!stopGate_.waitFor(kExpirySweepInterval)) {
            reapRetired();
            try {
                sweepExpired(nowSeconds());
            } catch (const std::exception& error) {
                bazarish::log::warn("destination expiry sweep failed: {}", error.what());
            }
        }
    });
}

void PerUserDestinations::revoke(const std::string& userFp)
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        std::error_code ec;
        std::filesystem::remove(pathFor(userFp), ec);
        if (ec) {
            bazarish::log::warn("revoked destination record for {} not removed: {}",
                bazarish::log::redact(userFp), ec.message());
        }
        teardownLocked(userFp);
    }
    reapRetired();
}

void PerUserDestinations::reloadPersisted(const std::int64_t now)
{
    startSweeper();
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
            if (expiresUnix <= now) {
                continue;
            }
            const std::string transientB64 = record.at("transient").get<std::string>();
            requireUsableDelegation(transientB64, expiresUnix);
            bringUp(entry.path().filename().string(), transientB64, expiresUnix,
                record.at("sealingKey").get<std::string>(),
                record.at("signingKey").get<std::string>());
        } catch (const std::exception& error) {
            bazarish::log::warn("destination record {} skipped at start: {}",
                bazarish::log::redact(entry.path().filename().string()), error.what());
        }
    }
}

void PerUserDestinations::setGetCard(GetCardFn getCard)
{
    getCard_ = std::move(getCard);
}

std::shared_ptr<bazarish::i2p::Endpoint> PerUserDestinations::endpointForDest(
    const std::string& dest) const
{
    if (dest.empty()) {
        return nullptr;
    }
    const std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& entry : dests_) {
        if (entry.second->dest == dest) {
            return entry.second->endpoint;
        }
    }
    return nullptr;
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
