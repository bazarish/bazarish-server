// Bazarish project (c) 2026
#include "DiskStorage.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Tokens.hpp>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <stdexcept>

// Minimal test support, mirroring the common library tests.
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

    // --- Identifier validation ---
    CHECK_THROWS(storage.registerClient("not-a-user", "client1"));
    CHECK_THROWS(storage.registerClient(alice, "../escape"));
    CHECK_THROWS(storage.putBlob(alice, "bad/blob", Bytes{1}, "content", kNow, kQuota));
    CHECK_THROWS(storage.putBlob(alice, "", Bytes{1}, "content", kNow, kQuota));

    // --- Client registry ---
    CHECK(!storage.isClientRegistered(alice, "client1"));
    storage.registerClient(alice, "client1");
    storage.registerClient(alice, "client2");
    storage.registerClient(alice, "client1");  // idempotent
    CHECK(storage.isClientRegistered(alice, "client1"));
    CHECK(storage.listClients(alice).size() == 2);

    // --- Token hashes ---
    const Bytes token1 = generateDeliveryToken();
    const Bytes token2 = generateDeliveryToken();
    storage.registerTokenHashes(alice, {deliveryTokenHash(token1), deliveryTokenHash(token2)});
    CHECK(storage.tokenHashCount(alice) == 2);
    CHECK(storage.consumeTokenHash(alice, deliveryTokenHash(token1)));
    // One-time: the second consume of the same hash fails.
    CHECK(!storage.consumeTokenHash(alice, deliveryTokenHash(token1)));
    CHECK(storage.tokenHashCount(alice) == 1);
    // The other one is spent the same way, and a spent hash is gone for good.
    CHECK(storage.consumeTokenHash(alice, deliveryTokenHash(token2)));
    CHECK(storage.tokenHashCount(alice) == 0);
    CHECK(!storage.consumeTokenHash(alice, deliveryTokenHash(token2)));

    // --- Pending content: put, dedup, quota ---
    const Bytes blob(100, 0xab);
    CHECK(storage.putBlob(alice, "msg1", blob, "content", kNow, kQuota) == Storage::PutResult::eStored);
    CHECK(storage.putBlob(alice, "msg1", blob, "content", kNow, kQuota) == Storage::PutResult::eDuplicate);
    CHECK(storage.usage(alice) == 100);
    CHECK(storage.hasBlob(alice, "msg1"));
    CHECK(!storage.hasBlob(alice, "nosuchblob"));
    CHECK(storage.getBlob(alice, "msg1") == blob);
    CHECK_THROWS(storage.getBlob(alice, "nosuchblob"));

    const Bytes bigBlob(static_cast<std::size_t>(kQuota), 0xcd);
    CHECK(storage.putBlob(alice, "msg2", bigBlob, "content", kNow, kQuota)
        == Storage::PutResult::eQuotaExceeded);
    CHECK(storage.usage(alice) == 100);

    // --- Pending list and the delete-when-all-acked rule ---
    CHECK((storage.listPending(alice, "client1")
        == std::vector<Storage::PendingEntry>{{"msg1", "content"}}));
    storage.ackBlob(alice, "msg1", "client1");
    CHECK(storage.listPending(alice, "client1").empty());
    // client2 has not acked: the blob must survive.
    CHECK((storage.listPending(alice, "client2")
        == std::vector<Storage::PendingEntry>{{"msg1", "content"}}));
    CHECK(storage.usage(alice) == 100);
    storage.ackBlob(alice, "msg1", "client2");
    // All registered clients acked: deleted immediately.
    CHECK(storage.usage(alice) == 0);
    CHECK(storage.listPending(alice, "client2").empty());
    // Acking a deleted blob is a no-op.
    storage.ackBlob(alice, "msg1", "client2");

    // --- Retiring a client re-evaluates completeness ---
    CHECK(storage.putBlob(alice, "msg3", blob, "content", kNow, kQuota) == Storage::PutResult::eStored);
    storage.ackBlob(alice, "msg3", "client1");
    CHECK(storage.usage(alice) == 100);
    storage.unregisterClient(alice, "client2");
    CHECK(storage.usage(alice) == 0);

    // --- A user with no registered clients keeps content until the sweep ---
    storage.unregisterClient(alice, "client1");
    CHECK(storage.putBlob(alice, "msg4", blob, "content", kNow, kQuota) == Storage::PutResult::eStored);
    CHECK(storage.usage(alice) == 100);

    // --- TTL sweep ---
    const std::string bob = makeUser(0x02);
    storage.registerClient(bob, "bclient");
    CHECK(storage.putBlob(bob, "old", blob, "content", kNow - 100, kQuota) == Storage::PutResult::eStored);
    CHECK(storage.putBlob(bob, "fresh", blob, "contact", kNow + 100, kQuota) == Storage::PutResult::eStored);
    storage.purgeExpired(kNow);
    CHECK((storage.listPending(bob, "bclient")
        == std::vector<Storage::PendingEntry>{{"fresh", "contact"}}));
    // Alice's msg4 (receivedAt == kNow) survives a sweep with threshold kNow.
    CHECK(storage.usage(alice) == 100);

    // --- Replay markers (seen-deliveryId cache): set, query, TTL sweep ---
    CHECK(!storage.hasSeen(bob, "nonce-fresh"));
    storage.markSeen(bob, "nonce-fresh", kNow + 100);
    storage.markSeen(bob, "nonce-stale", kNow - 100);
    CHECK(storage.hasSeen(bob, "nonce-fresh"));
    CHECK(storage.hasSeen(bob, "nonce-stale"));
    storage.purgeExpired(kNow);
    CHECK(storage.hasSeen(bob, "nonce-fresh"));   // kept
    CHECK(!storage.hasSeen(bob, "nonce-stale"));  // aged out on the blob horizon

    // --- forgetUser leaves nothing behind: the account is gone, not emptied ---
    storage.forgetUser(bob);
    CHECK(storage.usage(bob) == 0);
    CHECK(storage.listPending(bob, "bclient").empty());
    CHECK(!storage.hasSeen(bob, "nonce-fresh"));
    CHECK(!storage.isClientRegistered(bob, "bclient"));
    CHECK(storage.tokenHashCount(bob) == 0);

    // --- Per-user storage quota override ---
    const std::string dave = makeUser(0x42);
    CHECK(storage.userQuota(dave, kQuota) == kQuota);  // no override -> fallback
    storage.setUserQuota(dave, 8);
    CHECK(storage.userQuota(dave, kQuota) == 8);        // override returned
    CHECK(storage.userQuota(alice, kQuota) == kQuota);  // unrelated user unaffected
    CHECK(storage.putBlob(dave, "tiny", Bytes{1, 2, 3}, "content", kNow, 8)
        == Storage::PutResult::eStored);
    // Over the per-user quota - refused even though kQuota would allow it.
    CHECK(storage.putBlob(dave, "over", Bytes(20, 'x'), "content", kNow,
              storage.userQuota(dave, kQuota))
        == Storage::PutResult::eQuotaExceeded);

    // --- Persistence across instances ---
    DiskStorage reopened(root);
    CHECK(reopened.usage(alice) == 100);
    CHECK(reopened.getBlob(alice, "msg4") == blob);
    CHECK(reopened.userQuota(dave, kQuota) == 8);  // override persisted

    std::filesystem::remove_all(root);
    return 0;
}
