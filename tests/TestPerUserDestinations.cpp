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
        PerUserDestinations dests("127.0.0.1", 1, engine, root, I2pPrivacy::kMinimal);

        // Provision persists the transient and registers the destination.
        dests.provision(alice, "transient-blob-A", kNow + 1000);
        CHECK(std::filesystem::exists(aliceFile));
        CHECK(readFile(aliceFile).find("transient-blob-A") != std::string::npos);
        CHECK(dests.size() == 1);

        // Same transient: a no-op (still one destination).
        dests.provision(alice, "transient-blob-A", kNow + 1000);
        CHECK(dests.size() == 1);

        // A different transient replaces it (file updated, still one destination).
        dests.provision(alice, "transient-blob-B", kNow + 1000);
        CHECK(dests.size() == 1);
        CHECK(readFile(aliceFile).find("transient-blob-B") != std::string::npos);

        // Revoke forgets the destination and deletes the persisted transient.
        dests.revoke(alice);
        CHECK(!std::filesystem::exists(aliceFile));
        CHECK(dests.size() == 0);
    }

    // reloadPersisted re-provisions non-expired transients and skips expired ones.
    const std::string bob = toBase32(Bytes(32, 0x02));
    {
        PerUserDestinations writer("127.0.0.1", 1, engine, root, I2pPrivacy::kMinimal);
        writer.provision(alice, "transient-reload", kNow + 1000);
        writer.provision(bob, "transient-expired", kNow - 10);
    }
    {
        PerUserDestinations reloaded("127.0.0.1", 1, engine, root, I2pPrivacy::kMinimal);
        reloaded.reloadPersisted(kNow);
        CHECK(reloaded.size() == 1);  // alice restored; bob's expired transient skipped
    }

    std::printf("TestPerUserDestinations OK\n");
    return 0;
}
