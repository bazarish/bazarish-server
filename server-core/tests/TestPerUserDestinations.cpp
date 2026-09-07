// Bazarish project (c) 2026
#include "PerUserDestinations.hpp"

#include "DeliveryEngine.hpp"
#include "DiskStorage.hpp"

#include <nlohmann/json.hpp>

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

// A persisted record field (e.g. "sealingKey" / "signingKey") of a per-user dest.
std::string fieldOf(const std::filesystem::path& path, const char* key)
{
    const nlohmann::json record = nlohmann::json::parse(readFile(path));
    return record.value(key, std::string());
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

    // With no live router, each destination's worker cannot publish: the test
    // exercises persistence and lifecycle without a live I2P transport.
    {
        PerUserDestinations dests(nullptr, engine, root, bazarish::i2p::Privacy::eMinimal);

        // Real transients, because what may be reused across a provision turns
        // on the address they serve, and only a real blob has one. Two issued
        // from one master are a renewal: same address, different blob.
        const bazarish::i2p::Keys master = bazarish::i2p::Keys::generate();
        const std::string transientA = toBase64(master.issueTransient(kNow + 1000).blob());
        const std::string transientB = toBase64(master.issueTransient(kNow + 2000).blob());
        const std::string movedAway
            = toBase64(bazarish::i2p::Keys::generate().issueTransient(kNow + 1000).blob());

        // Provision persists the transient and registers the destination.
        dests.provision(alice, transientA, kNow + 1000);
        CHECK(std::filesystem::exists(aliceFile));
        CHECK(readFile(aliceFile).find(transientA) != std::string::npos);
        CHECK(dests.size() == 1);

        // The destination has a serving sealing key, persisted and surfaced for
        // the user's contact card. Its address stays empty here (no live router,
        // so the destination never publishes).
        const std::shared_ptr<Key> servingKeyA = dests.servingKeyFor(alice);
        CHECK(servingKeyA != nullptr);
        const Bytes servingA = servingKeyA->publicDer();
        CHECK(readFile(aliceFile).find("sealingKey") != std::string::npos);
        CHECK(dests.destinationFor(alice).empty());

        // The destination also carries its own per-destination federation signing
        // key (it signs this dest's delivered-acks), persisted bound to the dest
        // and distinct from the sealing key. Never the server root identity.
        CHECK(readFile(aliceFile).find("signingKey") != std::string::npos);
        const std::string signingA = fieldOf(aliceFile, "signingKey");
        CHECK(!signingA.empty());
        CHECK(signingA != fieldOf(aliceFile, "sealingKey"));

        // State: provisioned but the session never published (no router) and the
        // transient is still in date -> "building"; past its expiry -> "expired";
        // an unknown user -> "".
        CHECK(dests.stateFor(alice, kNow) == "building");
        CHECK(dests.stateFor(alice, kNow + 2000) == "expired");
        CHECK(dests.stateFor("nobody", kNow).empty());

        // Same transient: a no-op (still one destination).
        dests.provision(alice, transientA, kNow + 1000);
        CHECK(dests.size() == 1);

        // A renewal - a fresh transient of the same master, so the same address.
        // The file is updated and the keys are reused, or every contact holding
        // this user's card would stop being able to write to them.
        dests.provision(alice, transientB, kNow + 2000);
        CHECK(dests.size() == 1);
        CHECK(readFile(aliceFile).find(transientB) != std::string::npos);
        CHECK(dests.servingKeyFor(alice)->publicDer() == servingA);
        CHECK(fieldOf(aliceFile, "signingKey") == signingA);

        // Moving to another master is not a renewal: the address changes, the
        // old one is being left behind, and the keys must not follow it there.
        // The signature on a delivery confirmation is public - it goes back to
        // anyone who delivered, a stranger whose contact request was merely
        // stored included - so a signer carried across would let them prove the
        // new address is the same person.
        dests.provision(alice, movedAway, kNow + 1000);
        CHECK(dests.size() == 1);
        CHECK(dests.servingKeyFor(alice)->publicDer() != servingA);
        CHECK(fieldOf(aliceFile, "signingKey") != signingA);

        // And back to the address it started on, which is a fresh start of its
        // own: nothing of the abandoned one comes back either.
        dests.provision(alice, transientA, kNow + 1000);
        CHECK(fieldOf(aliceFile, "signingKey") != signingA);

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
        PerUserDestinations writer(nullptr, engine, root, bazarish::i2p::Privacy::eMinimal);
        writer.provision(alice, "transient-reload", kNow + 1000);
        writer.provision(bob, "transient-expired", kNow - 10);
        // Two users on distinct personal destinations get distinct signing keys -
        // no shared server-wide signer to cluster them as co-located.
        CHECK(fieldOf(root / "i2p-user-dests" / bob, "signingKey")
            != fieldOf(aliceFile, "signingKey"));
        const std::shared_ptr<Key> key = writer.servingKeyFor(alice);
        CHECK(key != nullptr);
        aliceServing = key->publicDer();
    }
    {
        PerUserDestinations reloaded(nullptr, engine, root, bazarish::i2p::Privacy::eMinimal);
        reloaded.reloadPersisted(kNow);
        CHECK(reloaded.size() == 1);  // alice restored; bob's expired transient skipped
        // The serving key survives the restart (the user's card stays valid).
        CHECK(reloaded.servingKeyFor(alice)->publicDer() == aliceServing);
    }

    // A delegation is a term, not a gift: once it runs out the destination comes
    // down and its record goes with it, so a restart does not raise it again.
    {
        PerUserDestinations dests(nullptr, engine, root, bazarish::i2p::Privacy::eMinimal);
        dests.provision(alice, "transient-lapsing", kNow + 100);
        CHECK(dests.size() == 1);
        CHECK(dests.sweepExpired(kNow) == 0);  // still within its term
        CHECK(dests.size() == 1);
        CHECK(dests.sweepExpired(kNow + 101) == 1);
        CHECK(dests.size() == 0);
        CHECK(!std::filesystem::exists(root / "i2p-user-dests" / alice));
    }
    {
        PerUserDestinations reloaded(nullptr, engine, root, bazarish::i2p::Privacy::eMinimal);
        reloaded.reloadPersisted(kNow);
        CHECK(reloaded.size() == 0);  // nothing left to bring back
    }

    std::printf("TestPerUserDestinations OK\n");
    return 0;
}
