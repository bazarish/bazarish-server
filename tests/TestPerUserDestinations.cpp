// Bazarish project (c) 2026
#include "PerUserDestinations.hpp"

#include "DeliveryEngine.hpp"
#include "DiskStorage.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

using namespace bazarish;
using namespace bazarish::server;

namespace {

constexpr std::int64_t kNow = 1780000000;

std::string readFile(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

}  // namespace

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-peruserdest-test";
    std::filesystem::remove_all(root);
    DiskStorage storage(root);

    const Key sealing = Key::generateSealing();
    DeliveryEngine engine(storage, toBase32(Bytes(32, 0xee)),
        Key::fromPrivatePem(sealing.privatePem()), DeliveryEngineOptions{});

    const std::string alice = toBase32(Bytes(32, 0x01));
    const std::filesystem::path aliceFile = root / "i2p-user-dests" / alice;

    // Port 1 is closed, so each destination's worker fails its SAM session fast:
    // the test exercises persistence and lifecycle without a live router.
    {
        PerUserDestinations dests("127.0.0.1", 1, engine, root, I2pPrivacy::eMinimal);

        // Provision persists the transient and registers the destination.
        dests.provision(alice, "transient-blob-A", kNow + 1000);
        CHECK(std::filesystem::exists(aliceFile));
        CHECK(readFile(aliceFile).find("transient-blob-A") != std::string::npos);
        CHECK(dests.size() == 1);

        // The destination has a serving sealing key, persisted and surfaced for
        // the user's contact card. Its address stays empty here (no SAM router,
        // so the session never publishes).
        const std::shared_ptr<Key> servingKeyA = dests.servingKeyFor(alice);
        CHECK(servingKeyA != nullptr);
        const Bytes servingA = servingKeyA->publicDer();
        CHECK(readFile(aliceFile).find("sealingKey") != std::string::npos);
        CHECK(dests.destinationFor(alice).empty());

        // Same transient: a no-op (still one destination).
        dests.provision(alice, "transient-blob-A", kNow + 1000);
        CHECK(dests.size() == 1);

        // A different transient replaces it (file updated, still one destination),
        // but the serving key is reused so the user's card stays valid.
        dests.provision(alice, "transient-blob-B", kNow + 1000);
        CHECK(dests.size() == 1);
        CHECK(readFile(aliceFile).find("transient-blob-B") != std::string::npos);
        CHECK(dests.servingKeyFor(alice)->publicDer() == servingA);

        // Revoke forgets the destination and deletes the persisted transient.
        dests.revoke(alice);
        CHECK(!std::filesystem::exists(aliceFile));
        CHECK(dests.size() == 0);
        CHECK(dests.servingKeyFor(alice) == nullptr);
    }

    // reloadPersisted re-provisions non-expired transients and skips expired ones.
    const std::string bob = toBase32(Bytes(32, 0x02));
    Bytes aliceServing;
    {
        PerUserDestinations writer("127.0.0.1", 1, engine, root, I2pPrivacy::eMinimal);
        writer.provision(alice, "transient-reload", kNow + 1000);
        writer.provision(bob, "transient-expired", kNow - 10);
        const std::shared_ptr<Key> key = writer.servingKeyFor(alice);
        CHECK(key != nullptr);
        aliceServing = key->publicDer();
    }
    {
        PerUserDestinations reloaded("127.0.0.1", 1, engine, root, I2pPrivacy::eMinimal);
        reloaded.reloadPersisted(kNow);
        CHECK(reloaded.size() == 1);  // alice restored; bob's expired transient skipped
        // The serving key survives the restart (the user's card stays valid).
        CHECK(reloaded.servingKeyFor(alice)->publicDer() == aliceServing);
    }

    std::printf("TestPerUserDestinations OK\n");
    return 0;
}
