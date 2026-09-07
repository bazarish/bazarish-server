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
#include <functional>
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
// How many accepted streams one destination serves at a time. Serving strictly
// one at a time is what made a delivery queue behind a slow or silent peer with
// no bound and no timeout: the sender saw "sending" for as long as the one in
// front took, which was minutes.
constexpr std::size_t kServeWorkers = 3;
// How long one inbound serve may take before the stream is closed under it. An
// I2P read has no deadline of its own, so without this a peer that opens a
// stream and then says nothing holds a worker for good.
constexpr int kServeDeadlineSeconds = 45;
// How often the watchdog looks for a serve that has outstayed that.
constexpr int kWatchdogTickSeconds = 2;
// How long a worker waits between checks for its destination to finish building.
constexpr int kEndpointPollMillis = 200;


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
    {
        const std::lock_guard<std::mutex> lock(stopMutex_);
        stopping_ = true;
    }
    stopCv_.notify_all();
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
    // Outside mutex_, always: a worker takes it once per request, and joining a
    // worker while holding it is a deadlock that never ends.
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
        while (true) {
            {
                std::unique_lock<std::mutex> lock(stopMutex_);
                if (stopCv_.wait_for(lock, std::chrono::seconds(kWatchdogTickSeconds),
                        [this]() { return stopping_; })) {
                    return;
                }
            }
            const std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
            const std::lock_guard<std::mutex> lock(watchMutex_);
            for (const auto& entry : watched_) {
                const std::shared_ptr<bazarish::i2p::Stream> held = entry.first.lock();
                if (held && entry.second <= now) {
                    // The peer opened a stream and stopped talking. Closing it is
                    // what turns that into one failed serve instead of a worker
                    // this destination never gets back.
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
        // The extra workers wait for the destination to build, then serve beside
        // the one that built it: one accepted stream must not hold up the next.
        for (std::size_t i = 1; i < kServeWorkers; ++i) {
            raw->workers.emplace_back([this, raw, userFp]() { serveLoop(raw, userFp); });
        }
        raw->workers.emplace_back([this, raw, transientB64, userFp]() {
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
                serveLoop(raw, userFp);
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
        return;  // torn down before it ever built
    }
    while (raw->running.load()) {
        std::string peer;
        const std::shared_ptr<bazarish::i2p::Stream> stream
            = endpoint->accept(peer, std::chrono::seconds(kAcceptTimeoutSeconds));
        if (!stream) {
            continue;  // accept timeout / stop
        }
        // Asked again here, not only above: between the accept and the lock
        // below a teardown may have started, and walking into that lock is
        // walking into the thread that is waiting for this one to end.
        if (!raw->running.load()) {
            stream->close();
            return;
        }
        try {
            // Snapshotted per request under the lock: a rotation replaces this
            // key while the loop is running, and the loop must serve with
            // whichever one is in force now.
            std::shared_ptr<Key> serving;
            std::shared_ptr<Key> signingKey;
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                serving = raw->sealingKey;
                signingKey = raw->signingKey;
            }
            // An I2P read has no deadline of its own; this is the one it gets.
            watchStream(stream);
            federationServeOnce(*stream, engine_, nowSeconds(), peer, limiter_, serving.get(),
                userFp, getCard_,
                // Sign the confirmation that goes back in the reply, with THIS
                // destination's own key: bound to the destination that took the
                // delivery, never to the server's identity.
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
    {
        // Handed over, not joined: every caller of this holds mutex_, and each of
        // this destination's workers takes mutex_ once per request. Joining here
        // is the deadlock that stops every destination on the server, for good.
        const std::lock_guard<std::mutex> lock(retiringMutex_);
        retiring_.push_back(std::move(it->second));
    }
    dests_.erase(it);
}

namespace {

// The address a transient serves, which is the master's and therefore the same
// for every transient reissued from it. Empty when the blob will not parse -
// then nothing is reused, which is the safe way to be wrong.
std::string addressOfTransient(const std::string& transientB64)
{
    try {
        return bazarish::i2p::Keys::fromBlob(fromBase64(transientB64)).base32();
    } catch (const std::exception&) {
        // error-hiding: allowed - an unparseable blob is answered by minting
        // fresh keys, which the caller does when this is empty.
        return {};
    }
}

// What the persisted record says this user's address was, or empty.
std::string recordedAddress(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    const std::string text(
        (std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (text.empty()) {
        return {};
    }
    try {
        return nlohmann::json::parse(text).value("address", std::string());
    } catch (const std::exception&) {
        // error-hiding: allowed - a record that will not parse is treated as no
        // record, and the keys are minted afresh a few lines below.
        return {};
    }
}

}  // namespace

void PerUserDestinations::provision(const std::string& userFp, const std::string& transientB64,
    const std::int64_t expiresUnix)
{
    reapRetired();
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto existing = dests_.find(userFp);
    if (existing != dests_.end() && existing->second->transientB64 == transientB64) {
        return;  // already serving this exact transient
    }
    // Reuse a previously-issued serving sealing key and federation signing key so
    // the user's contact card and signer stay stable across renewals - but only
    // across renewals. Keyed on the address rather than on the user: a transient
    // reissued from the same master keeps the address, and everything a contact
    // holds must go on working; a new master is a new address, and the old one is
    // being left behind.
    //
    // Carried across that boundary, the signer would undo the leaving. The
    // signature on a delivery confirmation is public - it goes back to whoever
    // delivered, including a stranger whose contact request was merely stored -
    // so anyone who kept one could prove the new address is the same person.
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
        {"address", address}, {"sealingKey", sealingKeyPem}, {"signingKey", signingKeyPem}};
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

namespace {

// Reads a destination record, hands it to `edit`, and writes it back. The record
// is the destination: a rotation that is not written down is one the next start
// knows nothing about.
void rewriteRecord(const std::filesystem::path& file,
    const std::function<void(nlohmann::json&)>& edit)
{
    nlohmann::json record = nlohmann::json::object();
    {
        std::ifstream in(file, std::ios::binary);
        const std::string text(
            (std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        if (!text.empty()) {
            record = nlohmann::json::parse(text);
        }
    }
    edit(record);
    const std::string text = record.dump();
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    out.close();
    if (!out) {
        throw std::runtime_error("cannot persist the destination record for " + file.string());
    }
}

}  // namespace

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
                // Left behind, the record brings the address back at the next
                // start - the one thing this sweep exists to prevent.
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

std::string PerUserDestinations::prepareServingKey(const std::string& userFp)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto found = dests_.find(userFp);
    if (found == dests_.end()) {
        throw std::runtime_error("no destination to rotate a serving key for");
    }
    const Key fresh = Key::generateSealing();
    rewriteRecord(pathFor(userFp), [&fresh](nlohmann::json& record) {
        record["pendingSealingKey"] = fresh.privatePem();
    });
    found->second->pendingSealingKey = std::make_shared<Key>(Key::fromPrivatePem(fresh.privatePem()));
    return toBase64(found->second->pendingSealingKey->publicDer());
}

bool PerUserDestinations::commitServingKey(const std::string& userFp)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto found = dests_.find(userFp);
    if (found == dests_.end() || !found->second->pendingSealingKey) {
        return false;
    }
    const std::string pem = found->second->pendingSealingKey->privatePem();
    rewriteRecord(pathFor(userFp), [&pem](nlohmann::json& record) {
        record["sealingKey"] = pem;
        record.erase("pendingSealingKey");
    });
    found->second->sealingKey = found->second->pendingSealingKey;
    found->second->pendingSealingKey.reset();
    bazarish::log::info("serving key rotated for {}", bazarish::log::redact(userFp));
    return true;
}

// How often the delegations are checked for having run out. They are measured in
// days, so this only has to be far finer than that.
constexpr std::chrono::minutes kExpirySweepInterval{10};

void PerUserDestinations::startSweeper()
{
    if (sweeper_.joinable()) {
        return;
    }
    startWatchdog();
    sweeper_ = std::thread([this]() {
        for (;;) {
            std::unique_lock<std::mutex> lock(stopMutex_);
            if (stopCv_.wait_for(lock, kExpirySweepInterval, [this]() { return stopping_; })) {
                return;
            }
            lock.unlock();
            // Whatever the last sweep or a revoke took out of service is joined
            // here, on a thread that holds no lock of ours.
            reapRetired();
            try {
                sweepExpired(nowSeconds());
            } catch (const std::exception& error) {
                // Housekeeping must not take the server down, but one that never
                // runs leaves addresses up past their term, so it is reported.
                bazarish::log::warn("destination expiry sweep failed: {}", error.what());
            }
        }
    });
}

void PerUserDestinations::revoke(const std::string& userFp)
{
    // Anything a previous teardown retired, joined here rather than under the
    // lock this method is about to take.
    reapRetired();
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
    startSweeper();
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
