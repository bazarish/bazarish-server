// Bazarish project (c) 2026
#include "DiskStorage.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Pass.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <thread>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

#define CHECK_THROWS(expression)                                                     \
    do {                                                                             \
        bool thrown = false;                                                         \
        try {                                                                        \
            (void)(expression);                                                      \
        } catch (const std::exception&) {                                            \
            thrown = true;                                                           \
        }                                                                            \
        if (!thrown) {                                                               \
            std::fprintf(stderr, "CHECK_THROWS failed at %s:%d: %s did not throw\n", \
                __FILE__, __LINE__, #expression);                                    \
            std::exit(1);                                                            \
        }                                                                            \
    } while (false)

using namespace bazarish;
using namespace bazarish::server;

namespace {

constexpr std::uint64_t kQuota = 1024;
constexpr std::int64_t kNow = 1780000000;

std::string makeUser(const unsigned char fill)
{
    return toBase32(Bytes(32, fill));
}

}  // namespace

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-storage-test";
    std::filesystem::remove_all(root);
    DiskStorage storage(root);

    const std::string alice = makeUser(0x01);

    CHECK_THROWS(storage.registerClient("not-a-user", "client1"));
    CHECK_THROWS(storage.registerClient(alice, "../escape"));
    CHECK_THROWS(storage.putBlob(alice, "bad/blob", Bytes{1}, "content", kQuota));
    CHECK_THROWS(storage.putBlob(alice, "", Bytes{1}, "content", kQuota));

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
    storage.registerPasses(alice, {handleBob, handleCarol});
    CHECK(storage.passCount(alice) == 2);
    for (int i = 0; i < 100; ++i) {
        CHECK(storage.hasPass(alice, handleBob));
    }
    CHECK(storage.passCount(alice) == 2);
    // Registering one already held is how a block is lifted, so it must not create a second entry.
    storage.registerPasses(alice, {handleBob});
    CHECK(storage.passCount(alice) == 2);
    CHECK(!storage.hasPass(alice, passBob));
    CHECK(!storage.hasPass(alice, Bytes{}));
    CHECK(!storage.hasPass(alice, Bytes(bazarish::kDeliveryPassSize - 1, 0x11)));
    CHECK_THROWS(storage.registerPasses(alice, {Bytes{1, 2, 3}}));

    CHECK(storage.revokePasses(alice, {handleBob}) == 1);
    CHECK(!storage.hasPass(alice, handleBob));
    CHECK(storage.hasPass(alice, handleCarol));
    CHECK(storage.passCount(alice) == 1);
    CHECK(storage.revokePasses(alice, {handleBob}) == 0);
    storage.registerPasses(alice, {handleBob});
    CHECK(storage.hasPass(alice, handleBob));

    const Bytes blob(100, 0xab);
    CHECK(storage.putBlob(alice, "msg1", blob, "content", kQuota) == Storage::PutResult::eStored);
    CHECK(storage.putBlob(alice, "msg1", blob, "content", kQuota) == Storage::PutResult::eDuplicate);
    CHECK(storage.usage(alice) == 100);
    CHECK(storage.hasBlob(alice, "msg1"));
    CHECK(!storage.hasBlob(alice, "nosuchblob"));
    CHECK(storage.getBlob(alice, "msg1") == blob);
    CHECK_THROWS(storage.getBlob(alice, "nosuchblob"));

    const Bytes bigBlob(static_cast<std::size_t>(kQuota), 0xcd);
    CHECK(storage.putBlob(alice, "msg2", bigBlob, "content", kQuota)
        == Storage::PutResult::eQuotaExceeded);
    CHECK(storage.usage(alice) == 100);

    CHECK((storage.listPending(alice, "client1")
        == std::vector<Storage::PendingEntry>{{"msg1", "content", blob.size()}}));
    {
        std::ofstream stray(root / "users" / alice / "blobs" / "msg9.tmp");
        stray << "half a delivery";
    }
    CHECK((storage.listPending(alice, "client1")
        == std::vector<Storage::PendingEntry>{{"msg1", "content", blob.size()}}));
    std::filesystem::remove(root / "users" / alice / "blobs" / "msg9.tmp");
    CHECK(storage.isPendingFor(alice, "msg1", "client1"));
    storage.ackBlob(alice, "msg1", "client1");
    CHECK(!storage.isPendingFor(alice, "msg1", "client1"));
    CHECK(storage.isPendingFor(alice, "msg1", "client2"));
    CHECK(!storage.isPendingFor(alice, "nosuchblob", "client2"));
    CHECK(storage.listPending(alice, "client1").empty());
    CHECK((storage.listPending(alice, "client2")
        == std::vector<Storage::PendingEntry>{{"msg1", "content", blob.size()}}));
    CHECK(storage.usage(alice) == 100);
    storage.ackBlob(alice, "msg1", "client2");
    CHECK(storage.usage(alice) == 0);
    CHECK(storage.listPending(alice, "client2").empty());
    storage.ackBlob(alice, "msg1", "client2");

    {
        constexpr auto kStampGap = std::chrono::milliseconds(2);
        CHECK(storage.putBlob(alice, "zzz", blob, "content", kQuota)
            == Storage::PutResult::eStored);
        std::this_thread::sleep_for(kStampGap);
        CHECK(storage.putBlob(alice, "mmm", blob, "content", kQuota)
            == Storage::PutResult::eStored);
        std::this_thread::sleep_for(kStampGap);
        CHECK(storage.putBlob(alice, "aaa", blob, "content", kQuota)
            == Storage::PutResult::eStored);
        CHECK((storage.listPending(alice, "client1")
            == std::vector<Storage::PendingEntry>{
                {"zzz", "content", blob.size()}, {"mmm", "content", blob.size()},
                {"aaa", "content", blob.size()}}));
        for (const char* const id : {"zzz", "mmm", "aaa"}) {
            storage.ackBlob(alice, id, "client1");
            storage.ackBlob(alice, id, "client2");
        }
        CHECK(storage.listPending(alice, "client1").empty());
    }

    CHECK(storage.putBlob(alice, "msg3", blob, "content", kQuota) == Storage::PutResult::eStored);
    storage.ackBlob(alice, "msg3", "client1");
    CHECK(storage.usage(alice) == 100);
    storage.unregisterClient(alice, "client2");
    CHECK(storage.usage(alice) == 0);

    storage.unregisterClient(alice, "client1");
    CHECK(storage.putBlob(alice, "msg4", blob, "content", kQuota) == Storage::PutResult::eStored);
    CHECK(storage.usage(alice) == 100);

    const std::string bob = makeUser(0x02);
    storage.registerClient(bob, "bclient");
    CHECK(storage.putBlob(bob, "old", blob, "content", kQuota) == Storage::PutResult::eStored);
    CHECK(storage.putBlob(bob, "fresh", blob, "contact", kQuota) == Storage::PutResult::eStored);
    storage.purgeExpired(kNow);
    CHECK(storage.listPending(bob, "bclient").size() == 2);
    CHECK(storage.usage(bob) == 200);
    CHECK(storage.usage(alice) == 100);

    CHECK(!storage.hasSeen(bob, "nonce-fresh"));
    storage.markSeen(bob, "nonce-fresh", kNow + 100);
    storage.markSeen(bob, "nonce-stale", kNow - 100);
    CHECK(storage.hasSeen(bob, "nonce-fresh"));
    CHECK(storage.hasSeen(bob, "nonce-stale"));
    storage.purgeExpired(kNow);
    CHECK(storage.hasSeen(bob, "nonce-fresh"));
    CHECK(!storage.hasSeen(bob, "nonce-stale"));

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
    CHECK(storage.putBlob(dave, "tiny", Bytes{1, 2, 3}, "content", 8)
        == Storage::PutResult::eStored);
    CHECK(storage.putBlob(dave, "over", Bytes(20, 'x'), "content",
              storage.userQuota(dave, kQuota))
        == Storage::PutResult::eQuotaExceeded);

    DiskStorage reopened(root);
    CHECK(reopened.usage(alice) == 100);
    CHECK(reopened.getBlob(alice, "msg4") == blob);
    CHECK(reopened.userQuota(dave, kQuota) == 8);

    std::filesystem::remove_all(root);
    return 0;
}
