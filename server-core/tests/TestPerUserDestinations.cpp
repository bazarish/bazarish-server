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
        CHECK(refused([&] { guard.provision(alice, transientA, shortExpiry + 1); }));
        CHECK(refused([&] { guard.provision(alice, toBase64(master.blob()), shortExpiry); }));
        CHECK(!std::filesystem::exists(aliceFile));
    }

    {
        PerUserDestinations dests(nullptr, engine, root, bazarish::i2p::Privacy::eMinimal);

        const PerUserDestinations::Assignment served
            = dests.provision(alice, transientA, shortExpiry);
        CHECK(served.dest == addressA);
        CHECK(served.sealingKey != nullptr);
        CHECK(std::filesystem::exists(aliceFile));
        CHECK(readFile(aliceFile).find(transientA) != std::string::npos);
        CHECK(dests.size() == 1);

        const std::shared_ptr<Key> servingKeyA
            = dests.assignmentFor(alice, shortExpiry - 1).sealingKey;
        CHECK(servingKeyA != nullptr);
        const Bytes servingA = servingKeyA->publicDer();
        CHECK(readFile(aliceFile).find("sealingKey") != std::string::npos);
        CHECK(dests.assignmentFor(alice, shortExpiry - 1).dest == addressA);
        CHECK(dests.provision(alice, transientA, shortExpiry).dest == addressA);

        CHECK(readFile(aliceFile).find("signingKey") != std::string::npos);
        const std::string signingA = fieldOf(aliceFile, "signingKey");
        CHECK(!signingA.empty());
        CHECK(signingA != fieldOf(aliceFile, "sealingKey"));

        CHECK(dests.assignmentFor(alice, shortExpiry - 1).state == "building");
        CHECK(dests.assignmentFor(alice, shortExpiry + 1).state == "expired");
        CHECK(dests.assignmentFor("nobody", shortExpiry - 1).state == "none");

        dests.provision(alice, transientA, shortExpiry);
        CHECK(dests.size() == 1);

        CHECK(dests.provision(alice, transientB, longExpiry).dest == addressA);
        CHECK(dests.size() == 1);
        CHECK(readFile(aliceFile).find(transientB) != std::string::npos);
        CHECK(dests.assignmentFor(alice, shortExpiry - 1).sealingKey->publicDer() == servingA);
        CHECK(fieldOf(aliceFile, "signingKey") == signingA);

        dests.provision(alice, movedAway, movedAwayExpiry);
        CHECK(dests.size() == 1);
        CHECK(dests.assignmentFor(alice, shortExpiry - 1).sealingKey->publicDer() != servingA);
        CHECK(fieldOf(aliceFile, "signingKey") != signingA);

        dests.provision(alice, transientA, shortExpiry);
        CHECK(fieldOf(aliceFile, "signingKey") != signingA);

        const Bytes servingBeforeOffline
            = dests.assignmentFor(alice, shortExpiry - 1).sealingKey->publicDer();
        const std::string signingBeforeOffline = fieldOf(aliceFile, "signingKey");
        dests.takeOffline(alice);
        CHECK(dests.size() == 0);
        CHECK(dests.assignmentFor(alice, shortExpiry - 1).sealingKey == nullptr);
        CHECK(std::filesystem::exists(aliceFile));
        CHECK(readFile(aliceFile).find(transientA) == std::string::npos);
        CHECK(dests.provision(alice, transientA, shortExpiry).dest == addressA);
        CHECK(dests.assignmentFor(alice, shortExpiry - 1).sealingKey->publicDer()
            == servingBeforeOffline);
        CHECK(fieldOf(aliceFile, "signingKey") == signingBeforeOffline);

        dests.forget(alice);
        CHECK(!std::filesystem::exists(aliceFile));
        CHECK(dests.size() == 0);
        CHECK(dests.assignmentFor(alice, shortExpiry - 1).sealingKey == nullptr);
    }

    const std::string bob = toBase32(Bytes(32, 0x02));
    Bytes aliceServing;
    {
        PerUserDestinations writer(nullptr, engine, root, bazarish::i2p::Privacy::eMinimal);
        writer.provision(alice, transientB, longExpiry);
        writer.provision(bob, transientA, shortExpiry);
        CHECK(fieldOf(root / "i2p-user-dests" / bob, "signingKey")
            != fieldOf(aliceFile, "signingKey"));
        const std::shared_ptr<Key> key = writer.assignmentFor(alice, shortExpiry - 1).sealingKey;
        CHECK(key != nullptr);
        aliceServing = key->publicDer();
    }
    {
        PerUserDestinations reloaded(nullptr, engine, root, bazarish::i2p::Privacy::eMinimal);
        reloaded.reloadPersisted(shortExpiry + 1);
        CHECK(reloaded.size() == 1);
        CHECK(reloaded.assignmentFor(alice, shortExpiry - 1).sealingKey->publicDer()
            == aliceServing);
        reloaded.forget(bob);
    }

    Bytes servingBeforeLapse;
    {
        PerUserDestinations dests(nullptr, engine, root, bazarish::i2p::Privacy::eMinimal);
        dests.provision(alice, transientA, shortExpiry);
        servingBeforeLapse = dests.assignmentFor(alice, shortExpiry - 1).sealingKey->publicDer();
        CHECK(dests.size() == 1);
        CHECK(dests.sweepExpired(shortExpiry - 1) == 0);
        CHECK(dests.size() == 1);
        CHECK(dests.sweepExpired(shortExpiry + 1) == 1);
        CHECK(dests.size() == 0);
        CHECK(std::filesystem::exists(aliceFile));
        CHECK(readFile(aliceFile).find(transientA) == std::string::npos);
    }
    {
        PerUserDestinations reloaded(nullptr, engine, root, bazarish::i2p::Privacy::eMinimal);
        reloaded.reloadPersisted(shortExpiry - 1);
        CHECK(reloaded.size() == 0);
        reloaded.provision(alice, transientA, shortExpiry);
        CHECK(reloaded.assignmentFor(alice, shortExpiry - 1).sealingKey->publicDer()
            == servingBeforeLapse);
    }

    std::printf("TestPerUserDestinations OK\n");
    return 0;
}
