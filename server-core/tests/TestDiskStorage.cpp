// Bazarish project (c) 2026
#include "DiskStorage.hpp"
#include "TestUtil.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Pass.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::server;

namespace {

constexpr std::uint64_t kQuota = 1024;
constexpr std::int64_t kNow = 1780000000;
constexpr std::size_t kPassCap = 64;
constexpr std::size_t kRacers = 16;
constexpr std::size_t kHeldLimit = 5;

std::string makeUser(const unsigned char fill)
{
    return toBase32(Bytes(32, fill));
}

}  // namespace

int main()
{
    const std::filesystem::path root
        = testutil::freshDir("storage-test");
    DiskStorage storage(root);

    const std::string alice = makeUser(0x01);

    CHECK_THROWS(storage.registerClient("not-a-user", "client1"));
    CHECK_THROWS(storage.registerClient(alice, "../escape"));
    CHECK_THROWS(storage.putBlob(alice, "bad/blob", Bytes{1}, "content", kQuota, kNow));
    CHECK_THROWS(storage.putBlob(alice, "", Bytes{1}, "content", kQuota, kNow));

    CHECK(!storage.isClientRegistered(alice, "client1"));
    storage.registerClient(alice, "client1");
    storage.registerClient(alice, "client2");
    storage.registerClient(alice, "client1");
    CHECK(storage.isClientRegistered(alice, "client1"));
    CHECK(storage.listClients(alice).size() == 2);

    const Bytes secret = randomBytes(kDeliverySecretSize);
    const Bytes passBob = deliveryPass(secret, std::string(52, 'b'));
    const Bytes passCarol = deliveryPass(secret, std::string(52, 'c'));
    const Bytes handleBob = deliveryPassHandle(passBob);
    const Bytes handleCarol = deliveryPassHandle(passCarol);
    CHECK(storage.registerPasses(alice, {handleBob, handleCarol}, kPassCap));
    CHECK(storage.passCount(alice) == 2);
    CHECK(storage.hasPass(alice, handleBob));
    // Registering one already held is how a block is lifted, so it must not create a second entry.
    CHECK(storage.registerPasses(alice, {handleBob}, kPassCap));
    CHECK(storage.passCount(alice) == 2);
    CHECK(!storage.hasPass(alice, passBob));
    CHECK(!storage.hasPass(alice, Bytes{}));
    CHECK(!storage.hasPass(alice, Bytes(bazarish::kDeliveryPassSize - 1, 0x11)));
    CHECK_THROWS(storage.registerPasses(alice, {Bytes{1, 2, 3}}, kPassCap));

    CHECK(storage.revokePasses(alice, {handleBob}) == 1);
    CHECK(!storage.hasPass(alice, handleBob));
    CHECK(storage.hasPass(alice, handleCarol));
    CHECK(storage.passCount(alice) == 1);
    CHECK(storage.revokePasses(alice, {handleBob}) == 0);
    CHECK(storage.registerPasses(alice, {handleBob}, kPassCap));
    CHECK(storage.hasPass(alice, handleBob));

    const Bytes blob(100, 0xab);
    CHECK(storage.putBlob(alice, "msg1", blob, "content", kQuota, kNow) == DiskStorage::PutResult::eStored);
    CHECK(storage.putBlob(alice, "msg1", blob, "content", kQuota, kNow) == DiskStorage::PutResult::eDuplicate);
    CHECK(storage.usage(alice) == 100);
    CHECK(storage.hasBlob(alice, "msg1"));
    CHECK(!storage.hasBlob(alice, "nosuchblob"));
    CHECK(storage.getBlob(alice, "msg1") == blob);
    CHECK_THROWS(storage.getBlob(alice, "nosuchblob"));

    const Bytes bigBlob(static_cast<std::size_t>(kQuota), 0xcd);
    CHECK(storage.putBlob(alice, "msg2", bigBlob, "content", kQuota, kNow)
        == DiskStorage::PutResult::eQuotaExceeded);
    CHECK(storage.usage(alice) == 100);

    CHECK((storage.listPending(alice, "client1")
        == std::vector<DiskStorage::PendingEntry>{{"msg1", "content", blob.size()}}));
    {
        std::ofstream stray(root / "users" / alice / "blobs" / "msg9.tmp");
        stray << "half a delivery";
    }
    CHECK((storage.listPending(alice, "client1")
        == std::vector<DiskStorage::PendingEntry>{{"msg1", "content", blob.size()}}));
    {
        std::ofstream stray(root / "users" / alice / "blobs" / "msg8.tmp");
        stray << std::string(kQuota, 'x');
    }
    CHECK(storage.usage(alice) == blob.size());
    std::filesystem::remove(root / "users" / alice / "blobs" / "msg8.tmp");
    std::filesystem::remove(root / "users" / alice / "blobs" / "msg9.tmp");
    CHECK(storage.isPendingFor(alice, "msg1", "client1"));
    storage.ackBlob(alice, "msg1", "client1");
    CHECK(!storage.isPendingFor(alice, "msg1", "client1"));
    CHECK(storage.isPendingFor(alice, "msg1", "client2"));
    CHECK(!storage.isPendingFor(alice, "nosuchblob", "client2"));
    CHECK(storage.listPending(alice, "client1").empty());
    CHECK((storage.listPending(alice, "client2")
        == std::vector<DiskStorage::PendingEntry>{{"msg1", "content", blob.size()}}));
    CHECK(storage.usage(alice) == 100);
    storage.ackBlob(alice, "msg1", "client2");
    CHECK(storage.usage(alice) == 0);
    CHECK(storage.listPending(alice, "client2").empty());
    storage.ackBlob(alice, "msg1", "client2");

    {
        constexpr auto kStampGap = std::chrono::milliseconds(2);
        CHECK(storage.putBlob(alice, "zzz", blob, "content", kQuota, kNow)
            == DiskStorage::PutResult::eStored);
        std::this_thread::sleep_for(kStampGap);
        CHECK(storage.putBlob(alice, "mmm", blob, "content", kQuota, kNow)
            == DiskStorage::PutResult::eStored);
        std::this_thread::sleep_for(kStampGap);
        CHECK(storage.putBlob(alice, "aaa", blob, "content", kQuota, kNow)
            == DiskStorage::PutResult::eStored);
        CHECK((storage.listPending(alice, "client1")
            == std::vector<DiskStorage::PendingEntry>{
                {"zzz", "content", blob.size()}, {"mmm", "content", blob.size()},
                {"aaa", "content", blob.size()}}));
        for (const char* const id : {"zzz", "mmm", "aaa"}) {
            storage.ackBlob(alice, id, "client1");
            storage.ackBlob(alice, id, "client2");
        }
        CHECK(storage.listPending(alice, "client1").empty());
    }

    CHECK(storage.putBlob(alice, "msg3", blob, "content", kQuota, kNow) == DiskStorage::PutResult::eStored);
    storage.ackBlob(alice, "msg3", "client1");
    CHECK(storage.usage(alice) == 100);
    storage.unregisterClient(alice, "client2");
    CHECK(storage.usage(alice) == 0);

    storage.unregisterClient(alice, "client1");
    CHECK(storage.putBlob(alice, "msg4", blob, "content", kQuota, kNow) == DiskStorage::PutResult::eStored);
    CHECK(storage.usage(alice) == 100);

    const std::string bob = makeUser(0x02);
    storage.registerClient(bob, "bclient");
    CHECK(storage.putBlob(bob, "old", blob, "content", kQuota, kNow) == DiskStorage::PutResult::eStored);
    CHECK(storage.putBlob(bob, "fresh", blob, "contact", kQuota, kNow) == DiskStorage::PutResult::eStored);
    storage.purgeExpired(kNow);
    CHECK(storage.listPending(bob, "bclient").size() == 2);
    CHECK(storage.usage(bob) == 200);
    CHECK(storage.usage(alice) == 100);

    CHECK(!storage.hasSeen(bob, "nonce-fresh"));
    CHECK(storage.putBlob(bob, "nonce-fresh", blob, "content", kQuota, kNow + 100)
        == DiskStorage::PutResult::eStored);
    CHECK(storage.putBlob(bob, "nonce-stale", blob, "content", kQuota, kNow - 100)
        == DiskStorage::PutResult::eStored);
    CHECK(storage.hasSeen(bob, "nonce-fresh"));
    CHECK(storage.hasSeen(bob, "nonce-stale"));
    storage.purgeExpired(kNow);
    CHECK(storage.hasSeen(bob, "nonce-fresh"));
    CHECK(!storage.hasSeen(bob, "nonce-stale"));

    storage.ackBlob(bob, "nonce-fresh", "bclient");
    CHECK(!storage.hasBlob(bob, "nonce-fresh"));
    CHECK(storage.hasSeen(bob, "nonce-fresh"));
    CHECK(!std::filesystem::exists(root / "users" / bob / "meta" / "nonce-fresh.json"));

    storage.forgetUser(bob);
    CHECK(storage.usage(bob) == 0);
    CHECK(storage.listPending(bob, "bclient").empty());
    CHECK(!storage.hasSeen(bob, "nonce-fresh"));
    CHECK(!storage.isClientRegistered(bob, "bclient"));
    CHECK(storage.passCount(bob) == 0);

    const std::string dave = makeUser(0x42);
    CHECK(storage.userQuota(dave, kQuota) == kQuota);
    storage.setUserQuota(dave, 8);
    CHECK(storage.userQuota(dave, kQuota) == 8);
    CHECK(storage.userQuota(alice, kQuota) == kQuota);
    CHECK(storage.putBlob(dave, "tiny", Bytes{1, 2, 3}, "content", 8, kNow)
        == DiskStorage::PutResult::eStored);
    CHECK(storage.putBlob(dave, "over", Bytes(20, 'x'), "content",
              storage.userQuota(dave, kQuota), kNow)
        == DiskStorage::PutResult::eQuotaExceeded);

    {
        const std::string erin = makeUser(0x77);
        std::vector<std::thread> racers;
        for (std::size_t i = 0; i < kRacers; ++i) {
            racers.emplace_back([&storage, &erin, i]() {
                (void)storage.putBlob(erin, "contact-" + std::to_string(i), Bytes{1}, "contact",
                    kQuota, kNow, {}, kHeldLimit);
            });
        }
        for (std::thread& racer : racers) {
            racer.join();
        }
        CHECK(storage.countHeld(erin, "contact") == kHeldLimit);
        CHECK(storage.putBlob(erin, "contact-0", Bytes{1}, "contact", kQuota, kNow, {}, kHeldLimit)
            != DiskStorage::PutResult::eStored);

        racers.clear();
        for (std::size_t i = 0; i < kRacers; ++i) {
            racers.emplace_back([&storage, &erin]() {
                std::vector<Bytes> handles;
                for (std::size_t n = 0; n < kPassCap / kHeldLimit; ++n) {
                    handles.push_back(randomBytes(bazarish::kDeliveryPassSize));
                }
                (void)storage.registerPasses(erin, handles, kPassCap);
            });
        }
        for (std::thread& racer : racers) {
            racer.join();
        }
        CHECK(storage.passCount(erin) <= kPassCap);
    }

    DiskStorage reopened(root);
    CHECK(reopened.usage(alice) == 100);
    CHECK(reopened.getBlob(alice, "msg4") == blob);
    CHECK(reopened.userQuota(dave, kQuota) == 8);

    std::filesystem::remove_all(root);
    return 0;
}
