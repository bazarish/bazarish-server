// Bazarish project (c) 2026
#include "PerUserDestinations.hpp"

#include "Federation.hpp"

#include <nlohmann/json.hpp>

#include <cstdio>
#include <ctime>
#include <exception>
#include <fstream>
#include <iterator>
#include <system_error>
#include <utility>

namespace bazarish::server {

namespace {

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

}  // namespace

PerUserDestinations::PerUserDestinations(std::string samHost, const std::uint16_t samPort,
    DeliveryEngine& engine, std::filesystem::path stateDir, const I2pPrivacy privacy,
    FederationRateLimiter* const limiter)
    : samHost_(std::move(samHost))
    , samPort_(samPort)
    , engine_(engine)
    , stateDir_(std::move(stateDir))
    , privacy_(privacy)
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
    const std::int64_t expiresUnix)
{
    auto dest = std::make_unique<Destination>();
    dest->transientB64 = transientB64;
    dest->expiresUnix = expiresUnix;
    Destination* const raw = dest.get();
    // SAM session ids must be unique on the bridge; the fingerprint disambiguates.
    const std::string sessionId = "bazarish-user-" + userFp.substr(0, 12);
    raw->worker = std::thread([this, raw, sessionId, transientB64, userFp]() {
        try {
            // A STANDARD LeaseSet2: an offline-signature destination cannot
            // publish an encrypted LeaseSet2.
            SamSession session(samHost_, samPort_, sessionId, transientB64,
                kStandardLeaseSetType, privacy_);
            std::printf("per-user i2p destination up for %s\n", userFp.c_str());
            std::fflush(stdout);
            while (raw->running.load()) {
                try {
                    std::string peer;
                    SamStream stream = session.accept(peer);
                    federationServeOnce(stream, engine_, nowSeconds(), peer, limiter_);
                } catch (const std::exception&) {
                    // A failed accept/serve must not kill the loop; on shutdown
                    // the running flag breaks out on the next iteration.
                }
            }
        } catch (const std::exception&) {
            // Building the session failed (bad/expired transient, SAM down):
            // the destination stays down until the next provision.
        }
    });
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
    // Persist first so a restart re-provisions even if the bring-up below races.
    std::error_code ec;
    std::filesystem::create_directories(destsDir(), ec);
    const nlohmann::json record = {{"transient", transientB64}, {"expiresUnix", expiresUnix}};
    const std::string text = record.dump();
    {
        std::ofstream out(pathFor(userFp), std::ios::binary | std::ios::trunc);
        out.write(text.data(), static_cast<std::streamsize>(text.size()));
    }
    teardownLocked(userFp);
    bringUp(userFp, transientB64, expiresUnix);
}

void PerUserDestinations::revoke(const std::string& userFp)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    std::error_code ec;
    std::filesystem::remove(pathFor(userFp), ec);
    teardownLocked(userFp);
}

void PerUserDestinations::reloadPersisted(const std::int64_t now)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    std::error_code ec;
    if (!std::filesystem::exists(destsDir(), ec)) {
        return;
    }
    for (const auto& entry : std::filesystem::directory_iterator(destsDir(), ec)) {
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
            bringUp(entry.path().filename().string(), transientB64, expiresUnix);
        } catch (const std::exception&) {
            // Skip a malformed record rather than fail startup.
        }
    }
}

std::size_t PerUserDestinations::size() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return dests_.size();
}

}  // namespace bazarish::server
