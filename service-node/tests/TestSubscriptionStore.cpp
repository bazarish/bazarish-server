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

    CHECK(!store.getAccount(alice).has_value());
    SubscriptionStore::Account account{
        alice, 1000, 10485760, "destination.b32.i2p", 1500, "0123456789abcdef0123456789abcdef",
        /*pendingView=*/{}, /*pendingServingKey=*/{}, Bytes{0xaa, 0xbb}};
    store.putAccount(account);
    const auto loaded = store.getAccount(alice);
    CHECK(loaded.has_value());
    CHECK(loaded->user == alice);
    CHECK(loaded->registeredAt == 1000);
    CHECK(loaded->quotaBytes == 10485760);
    CHECK(loaded->card == (Bytes{0xaa, 0xbb}));
    CHECK(loaded->view == "0123456789abcdef0123456789abcdef");
    CHECK(loaded->dest == "destination.b32.i2p");
    CHECK(loaded->delegatedAt == 1500);
    store.deleteAccount(alice);
    CHECK(!store.getAccount(alice).has_value());

    store.putAccount(account);
    SubscriptionStore reopened(root);
    CHECK(reopened.getAccount(alice).has_value());
    CHECK(reopened.allAccounts().size() == 1);

    std::filesystem::remove_all(root);
    return 0;
}
