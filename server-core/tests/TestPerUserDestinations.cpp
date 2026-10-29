// Bazarish project (c) 2026
#include "PerUserDestinations.hpp"

#include "DeliveryEngine.hpp"
#include "DiskStorage.hpp"

#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <exception>
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

constexpr int kShortTermDays = 1;
constexpr int kLongTermDays = 2;

std::string readFile(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

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
        std::make_shared<Key>(Key::fromPrivatePem(sealing.privatePem())),
        DeliveryEngineOptions{});

    const std::string alice = toBase32(Bytes(32, 0x01));
    const std::filesystem::path aliceFile = root / "i2p-user-dests" / alice;

    const bazarish::i2p::Keys master = bazarish::i2p::Keys::generate();
    const bazarish::i2p::Keys shortTerm = master.issueTransient(kShortTermDays);
    const bazarish::i2p::Keys longTerm = master.issueTransient(kLongTermDays);
    const bazarish::i2p::Keys otherMaster
        = bazarish::i2p::Keys::generate().issueTransient(kShortTermDays);
    const std::string transientA = toBase64(shortTerm.blob());
    const std::string transientB = toBase64(longTerm.blob());
    const std::string movedAway = toBase64(otherMaster.blob());
    const std::string addressA = bazarish::i2p::routingHost(shortTerm.publicBase64());
    const std::int64_t shortExpiry = shortTerm.transientExpires();
    const std::int64_t longExpiry = longTerm.transientExpires();
    const std::int64_t movedAwayExpiry = otherMaster.transientExpires();
    CHECK(shortTerm.b33OfflineKeyDays() == kShortTermDays);
    CHECK(longTerm.b33OfflineKeyDays() == kLongTermDays);
    CHECK(longExpiry > shortExpiry);

    const Key sealingA = Key::generateSealing();
    const Key signingA = Key::generateSigning();
    const Key sealingB = Key::generateSealing();
    const Key signingB = Key::generateSigning();
    const auto sealingOf = [](const std::filesystem::path& path) {
        return Key::fromPrivatePem(fieldOf(path, "sealingKey")).publicDer();
    };
    const auto signingOf = [](const std::filesystem::path& path) {
        return Key::fromPrivatePem(fieldOf(path, "signingKey")).publicDer();
    };

    {
        PerUserDestinations guard(nullptr, engine, root, bazarish::i2p::Privacy::eMinimal);
        const auto refused = [](const auto& call) {
            try {
                call();
            } catch (const std::exception&) {
                return true;
            }
            return false;
        };
        const std::string sealingPem = sealingA.privatePem();
        const std::string signingPem = signingA.privatePem();
        CHECK(refused([&] {
            guard.provision(alice, transientA, shortExpiry + 1, sealingPem, signingPem);
        }));
        CHECK(refused([&] {
            guard.provision(alice, toBase64(master.blob()), shortExpiry, sealingPem, signingPem);
        }));
        CHECK(refused([&] { guard.provision(alice, transientA, shortExpiry, "", ""); }));
        CHECK(refused([&] {
            guard.provision(alice, transientA, shortExpiry, signingPem, signingPem);
        }));
        CHECK(refused([&] {
            guard.provision(alice, transientA, shortExpiry, sealingPem, sealingPem);
        }));
        CHECK(refused([&] {
            guard.provision(alice, transientA, shortExpiry, sealingA.kem().privatePem(),
                signingPem);
        }));
        CHECK(!std::filesystem::exists(aliceFile));
    }

    {
        PerUserDestinations dests(nullptr, engine, root, bazarish::i2p::Privacy::eMinimal);

        const PerUserDestinations::Assignment served = dests.provision(
            alice, transientA, shortExpiry, sealingA.privatePem(), signingA.privatePem());
        CHECK(served.dest == addressA);
        CHECK(served.sealingKey->publicDer() == sealingA.publicDer());
        CHECK(readFile(aliceFile).find(transientA) != std::string::npos);
        CHECK(sealingOf(aliceFile) == sealingA.publicDer());
        CHECK(signingOf(aliceFile) == signingA.publicDer());
        CHECK(dests.size() == 1);
        CHECK(dests.assignmentFor(alice, shortExpiry - 1).state == "building");
        CHECK(dests.assignmentFor(alice, shortExpiry + 1).state == "expired");
        CHECK(dests.assignmentFor("nobody", shortExpiry - 1).state == "none");

        CHECK(dests.provision(alice, transientB, longExpiry, sealingA.privatePem(),
                       signingA.privatePem())
                  .dest
            == addressA);
        CHECK(dests.size() == 1);
        CHECK(readFile(aliceFile).find(transientB) != std::string::npos);
        CHECK(dests.assignmentFor(alice, shortExpiry - 1).sealingKey->publicDer()
            == sealingA.publicDer());

        dests.provision(alice, transientB, longExpiry, sealingB.privatePem(), signingB.privatePem());
        CHECK(dests.assignmentFor(alice, shortExpiry - 1).sealingKey->publicDer()
            == sealingB.publicDer());
        CHECK(signingOf(aliceFile) == signingB.publicDer());

        dests.provision(
            alice, movedAway, movedAwayExpiry, sealingA.privatePem(), signingA.privatePem());
        CHECK(dests.size() == 1);
        CHECK(dests.assignmentFor(alice, shortExpiry - 1).dest
            == bazarish::i2p::routingHost(otherMaster.publicBase64()));

        dests.forget(alice);
        CHECK(!std::filesystem::exists(aliceFile));
        CHECK(dests.size() == 0);
        CHECK(dests.assignmentFor(alice, shortExpiry - 1).sealingKey == nullptr);
        dests.provision(alice, transientA, shortExpiry, sealingA.privatePem(), signingA.privatePem());
        CHECK(dests.assignmentFor(alice, shortExpiry - 1).sealingKey->publicDer()
            == sealingA.publicDer());
        dests.forget(alice);
    }

    const std::string bob = toBase32(Bytes(32, 0x02));
    {
        PerUserDestinations writer(nullptr, engine, root, bazarish::i2p::Privacy::eMinimal);
        writer.provision(alice, transientB, longExpiry, sealingA.privatePem(), signingA.privatePem());
        writer.provision(bob, transientA, shortExpiry, sealingB.privatePem(), signingB.privatePem());
    }
    {
        PerUserDestinations reloaded(nullptr, engine, root, bazarish::i2p::Privacy::eMinimal);
        reloaded.reloadPersisted(shortExpiry - kLapseLeadSeconds);
        CHECK(reloaded.size() == 1);
        CHECK(reloaded.assignmentFor(alice, shortExpiry - 1).sealingKey->publicDer()
            == sealingA.publicDer());
        reloaded.forget(bob);
        reloaded.forget(alice);
    }

    {
        PerUserDestinations dests(nullptr, engine, root, bazarish::i2p::Privacy::eMinimal);
        dests.provision(alice, transientA, shortExpiry, sealingA.privatePem(), signingA.privatePem());
        CHECK(dests.size() == 1);
        const std::int64_t goesDownAt = shortExpiry - kLapseLeadSeconds;
        constexpr std::int64_t kAhead = 30;
        CHECK(dests.nextSweepIn(goesDownAt - kAhead) == std::chrono::seconds(kAhead));
        CHECK(dests.nextSweepIn(goesDownAt) == std::chrono::seconds(0));
        CHECK(dests.sweepExpired(goesDownAt - 1) == 0);
        CHECK(dests.size() == 1);
        CHECK(dests.sweepExpired(goesDownAt) == 1);
        CHECK(dests.size() == 0);
        CHECK(!std::filesystem::exists(aliceFile));
    }

    std::printf("TestPerUserDestinations OK\n");
    return 0;
}
