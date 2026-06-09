// Bazarish project (c) 2026
#include "SubscriptionStore.hpp"

#include <bazarish/Bytes.hpp>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <stdexcept>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

using namespace bazarish;
using namespace bazarish::service;

namespace {

std::string makeUser(const unsigned char fill)
{
    return toBase32(Bytes(32, fill));
}

}  // namespace

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-subscription-test";
    std::filesystem::remove_all(root);
    SubscriptionStore store(root);

    const std::string alice = makeUser(0x01);
    const std::string bob = makeUser(0x02);

    // Subscriptions.
    CHECK(!store.getSubscription(alice).has_value());
    SubscriptionStore::Subscription sub{alice, 1000, 2000, 10485760, Bytes{0xaa, 0xbb}};
    store.putSubscription(sub);
    const auto loaded = store.getSubscription(alice);
    CHECK(loaded.has_value());
    CHECK(loaded->user == alice);
    CHECK(loaded->notAfter == 2000);
    CHECK(loaded->quotaBytes == 10485760);
    CHECK(loaded->certificate == (Bytes{0xaa, 0xbb}));
    store.deleteSubscription(alice);
    CHECK(!store.getSubscription(alice).has_value());

    // Aliases: register, ownership, conflicts.
    CHECK(store.putAlias({"alice", alice, Bytes{0x01}}));
    const auto aliasRecord = store.getAlias("alice");
    CHECK(aliasRecord.has_value());
    CHECK(aliasRecord->user == alice);
    // Re-registering one's own alias refreshes it.
    CHECK(store.putAlias({"alice", alice, Bytes{0x02}}));
    CHECK(store.getAlias("alice")->certificate == (Bytes{0x02}));
    // Another user cannot take it.
    CHECK(!store.putAlias({"alice", bob, Bytes{0x03}}));
    CHECK(store.getAlias("alice")->user == alice);
    // Non-owner cannot delete; owner can.
    CHECK(!store.deleteAlias("alice", bob));
    CHECK(store.getAlias("alice").has_value());
    CHECK(store.deleteAlias("alice", alice));
    CHECK(!store.getAlias("alice").has_value());

    // Validation.
    CHECK(!store.getAlias("nope").has_value());
    bool threw = false;
    try {
        store.putAlias({"Bad Alias", alice, Bytes{}});
    } catch (const std::exception&) {
        threw = true;
    }
    CHECK(threw);

    // Persistence across instances.
    store.putSubscription(sub);
    SubscriptionStore reopened(root);
    CHECK(reopened.getSubscription(alice).has_value());

    std::filesystem::remove_all(root);
    return 0;
}
