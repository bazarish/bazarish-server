// Bazarish project (c) 2026
#include "FederationPool.hpp"

#include "Federation.hpp"

#include <sys/stat.h>

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

FederationPool::FederationPool(std::string samHost, const std::uint16_t samPort,
    DeliveryEngine& engine, std::filesystem::path stateDir, std::string sessionIdPrefix,
    const I2pPrivacy privacy, const std::size_t size)
    : samHost_(std::move(samHost))
    , samPort_(samPort)
    , engine_(engine)
    , stateDir_(std::move(stateDir))
    , sessionIdPrefix_(std::move(sessionIdPrefix))
    , privacy_(privacy)
    , size_(size)
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
        const std::string privateKeys
            = std::filesystem::exists(keyPath) ? readFile(keyPath) : std::string("TRANSIENT");
        auto dest = std::make_unique<Dest>();
        // Encrypted LeaseSet2 (the default): a pool destination is server-owned,
        // so blinding has the signing key and the shareable address is a b33.
        dest->session = std::make_unique<SamSession>(samHost_, samPort_,
            sessionIdPrefix_ + std::to_string(i), privateKeys, kEncryptedLeaseSetType, privacy_);
        if (!std::filesystem::exists(keyPath)) {
            writePrivate(keyPath, dest->session->privateDestination());
        }
        destinations_.push_back(dest->session->publicDestination());
        Dest* const raw = dest.get();
        raw->acceptThread = std::thread([this, raw]() {
            while (raw->running.load()) {
                try {
                    std::string peer;
                    SamStream stream = raw->session->accept(peer);
                    federationServeOnce(stream, engine_, nowSeconds());
                } catch (const std::exception&) {
                    // A failed accept/serve must not kill the loop.
                }
            }
        });
        dests_.push_back(std::move(dest));
    }
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

const std::vector<std::string>& FederationPool::destinations() const
{
    return destinations_;
}

}  // namespace bazarish::server
