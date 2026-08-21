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

    // Subscriptions.
    CHECK(!store.getSubscription(alice).has_value());
    SubscriptionStore::Subscription sub{
        alice, 1000, 2000, 10485760, "destination.b32.i2p", Bytes{0xaa, 0xbb}};
    store.putSubscription(sub);
    const auto loaded = store.getSubscription(alice);
    CHECK(loaded.has_value());
    CHECK(loaded->user == alice);
    CHECK(loaded->notAfter == 2000);
    CHECK(loaded->quotaBytes == 10485760);
    CHECK(loaded->certificate == (Bytes{0xaa, 0xbb}));
    // The address is kept beside the certificate so a listing can show it.
    CHECK(loaded->dest == "destination.b32.i2p");
    store.deleteSubscription(alice);
    CHECK(!store.getSubscription(alice).has_value());

    // Persistence across instances.
    store.putSubscription(sub);
    SubscriptionStore reopened(root);
    CHECK(reopened.getSubscription(alice).has_value());

    std::filesystem::remove_all(root);
    return 0;
}
