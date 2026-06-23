// Bazarish project (c) 2026
#include "FederationPool.hpp"

#include "Federation.hpp"

#include <sys/stat.h>

#include <chrono>
#include <cstdint>
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

std::string readFile(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

void writePrivate(const std::filesystem::path& path, const std::string& data)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    out.close();
    ::chmod(path.c_str(), S_IRUSR | S_IWUSR);
}

}  // namespace

std::size_t poolIndexFor(const std::string& userFp, const std::size_t poolSize)
{
    if (poolSize == 0) {
        return 0;
    }
    // FNV-1a over the fingerprint: stable across restarts and platforms, unlike
    // std::hash, so a user keeps the same pool destination.
    std::uint64_t h = 1469598103934665603ULL;
    for (const char c : userFp) {
        h ^= static_cast<std::uint8_t>(c);
        h *= 1099511628211ULL;
    }
    return static_cast<std::size_t>(h % poolSize);
}

FederationPool::FederationPool(bazarish::i2p::Router& router, DeliveryEngine& engine,
    std::filesystem::path stateDir, const bazarish::i2p::Privacy privacy, const std::size_t size,
    const int tunnelQuantity, FederationRateLimiter* const limiter)
    : router_(router)
    , engine_(engine)
    , stateDir_(std::move(stateDir))
    , privacy_(privacy)
    , size_(size)
    , tunnelQuantity_(tunnelQuantity)
    , limiter_(limiter)
{
}

FederationPool::~FederationPool()
{
    stop();
    for (auto& dest : dests_) {
        if (dest->acceptThread.joinable()) {
            dest->acceptThread.join();
        }
    }
}

void FederationPool::start()
{
    const std::filesystem::path poolDir = stateDir_ / "pool";
    std::error_code ec;
    std::filesystem::create_directories(poolDir, ec);
    for (std::size_t i = 0; i < size_; ++i) {
        const std::filesystem::path keyPath = poolDir / ("dest-" + std::to_string(i) + ".key");
        const bool haveKey = std::filesystem::exists(keyPath);
        auto dest = std::make_unique<Dest>();
        // Encrypted LeaseSet2: a pool destination is server-owned, so blinding has
        // the signing key and the shareable address is a b33.
        const std::string rawKey = haveKey ? readFile(keyPath) : std::string();
        bazarish::i2p::Keys keys = haveKey
            ? bazarish::i2p::Keys::fromBlob(Bytes(rawKey.begin(), rawKey.end()))
            : bazarish::i2p::Keys::generate();
        dest->endpoint = router_.createEndpoint(bazarish::i2p::EndpointConfig{
            keys, bazarish::i2p::LeaseSetKind::eEncrypted, privacy_, tunnelQuantity_, true});
        if (!haveKey) {
            const Bytes blob = dest->endpoint->privateBlob();
            writePrivate(keyPath, std::string(blob.begin(), blob.end()));
        }
        // The pool entry's own serving sealing key (persisted so the address a
        // contact seals to is stable across restarts). Contacts on this pool
        // destination all seal to it - same k-anonymity set as the destination.
        const std::filesystem::path sealingPath
            = poolDir / ("dest-" + std::to_string(i) + ".sealing.pem");
        if (std::filesystem::exists(sealingPath)) {
            dest->sealingKey = std::make_shared<Key>(Key::fromPrivatePem(readFile(sealingPath)));
        } else {
            dest->sealingKey = std::make_shared<Key>(Key::generateSealing());
            writePrivate(sealingPath, dest->sealingKey->privatePem());
        }
        // The routable address is the b33 (pool destinations are encrypted LS2).
        destinations_.push_back(dest->endpoint->routingHost());
        servingKeys_.push_back(dest->sealingKey);
        Dest* const raw = dest.get();
        raw->acceptThread = std::thread([this, raw]() {
            while (raw->running.load()) {
                std::string peer;
                auto stream = raw->endpoint->accept(peer, std::chrono::seconds(30));
                if (!stream) {
                    continue;  // accept timeout / stop: re-check running
                }
                try {
                    federationServeOnce(*stream, engine_, nowSeconds(), peer, limiter_,
                        raw->sealingKey.get(), getCard_);
                } catch (const std::exception&) {
                    // A failed serve must not kill the loop.
                }
            }
        });
        dests_.push_back(std::move(dest));
    }
}

void FederationPool::setGetCard(GetCardFn getCard)
{
    getCard_ = std::move(getCard);
}

void FederationPool::stop()
{
    for (auto& dest : dests_) {
        dest->running = false;
    }
}

std::string FederationPool::destinationFor(const std::string& userFp) const
{
    if (destinations_.empty()) {
        return std::string();
    }
    return destinations_[poolIndexFor(userFp, destinations_.size())];
}

std::shared_ptr<Key> FederationPool::servingKeyFor(const std::string& userFp) const
{
    if (servingKeys_.empty()) {
        return nullptr;
    }
    return servingKeys_[poolIndexFor(userFp, servingKeys_.size())];
}

const std::vector<std::string>& FederationPool::destinations() const
{
    return destinations_;
}

}  // namespace bazarish::server
