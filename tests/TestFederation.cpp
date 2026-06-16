// Bazarish project (c) 2026
#include "Federation.hpp"

#include "DeliveryEngine.hpp"
#include "DiskStorage.hpp"

#include <bazarish/Cms.hpp>
#include <bazarish/Tokens.hpp>

#include <nlohmann/json.hpp>

#include <sys/socket.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <thread>

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

// Builds a sealed envelope addressed to the recipient server's sealing key.
Bytes makeSealed(const Key& sealingPublic, const std::string& kind,
    const std::string& mailbox, const std::string& messageId, const Bytes& token)
{
    nlohmann::json inner = {{"class", kind}, {"mailbox", mailbox}, {"messageId", messageId}};
    if (kind == "content") {
        inner["token"] = toBase64(token);
    }
    const std::string text = inner.dump();
    return cms::seal(Bytes(text.begin(), text.end()), sealingPublic);
}

// Runs one client deliver against an in-thread server using a socketpair —
// the same SamStream wraps both ends, so the federation protocol is
// exercised without I2P.
FederationDeliverResult roundTrip(DeliveryEngine& engine, const Bytes& sealed, const Bytes& payload,
    const Key* const servingKey = nullptr)
{
    int fds[2];
    CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    SamStream serverStream(fds[0]);
    SamStream clientStream(fds[1]);

    std::thread serverThread([&engine, &serverStream, servingKey]() {
        federationServeOnce(serverStream, engine, kNow, std::string(), nullptr, servingKey);
    });
    const FederationDeliverResult result
        = federationSendDeliver(clientStream, sealed, payload);
    serverThread.join();
    return result;
}

}  // namespace

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-federation-test";
    std::filesystem::remove_all(root);
    DiskStorage storage(root);

    const std::string alice = toBase32(Bytes(32, 0x01));
    const Key sealing = Key::generateSealing();
    const Key sealingPublic = Key::fromPublicDer(sealing.publicDer());
    DeliveryEngine engine(storage, toBase32(Bytes(32, 0xee)),
        Key::fromPrivatePem(sealing.privatePem()), DeliveryEngineOptions{});

    const Bytes token = generateDeliveryToken();
    storage.registerTokenHashes(alice, {deliveryTokenHash(token)});

    const Bytes payload = {'f', 'e', 'd', '-', 'b', 'l', 'o', 'b'};

    // Successful federated message delivery consumes the token.
    {
        const Bytes sealed = makeSealed(sealingPublic, "content", alice, "fmsg-1", token);
        const FederationDeliverResult result = roundTrip(engine, sealed, payload);
        CHECK(result.delivered);
        CHECK(storage.tokenHashCount(alice) == 0);
        CHECK(storage.getBlob(alice, "fmsg-1") == payload);
    }

    // Retry is deduplicated and does not need a (now spent) token.
    {
        const Bytes sealed = makeSealed(sealingPublic, "content", alice, "fmsg-1", token);
        const FederationDeliverResult result = roundTrip(engine, sealed, payload);
        CHECK(result.delivered);
    }

    // A bad token collapses into DELIVERY_REJECTED.
    {
        const Bytes sealed
            = makeSealed(sealingPublic, "content", alice, "fmsg-2", generateDeliveryToken());
        const FederationDeliverResult result = roundTrip(engine, sealed, payload);
        CHECK(!result.delivered);
        CHECK(result.errorCode == "DELIVERY_REJECTED");
    }

    // Tokenless contact request is admitted.
    {
        const Bytes sealed = makeSealed(sealingPublic, "contact", alice, "freq-1", {});
        const FederationDeliverResult result = roundTrip(engine, sealed, Bytes(100, 0x33));
        CHECK(result.delivered);
        CHECK(storage.getBlob(alice, "freq-1").size() == 100);
    }

    // Replay protection: a tokenless contact request that was delivered, then
    // fetched and acked away, must not be re-injected when its envelope is
    // replayed. Without the seen-cache nothing would stop the second store.
    {
        storage.registerClient(alice, "client01");
        const Bytes sealed = makeSealed(sealingPublic, "contact", alice, "freq-replay", {});

        CHECK(roundTrip(engine, sealed, Bytes(100, 0x44)).delivered);
        CHECK(storage.hasBlob(alice, "freq-replay"));

        // The recipient consumes it: ack drops the blob from the mailbox.
        storage.ackBlob(alice, "freq-replay", "client01");
        CHECK(!storage.hasBlob(alice, "freq-replay"));

        // Replaying the exact same envelope reports success (idempotent) but
        // does not put the message back into the mailbox.
        CHECK(roundTrip(engine, sealed, Bytes(100, 0x44)).delivered);
        CHECK(!storage.hasBlob(alice, "freq-replay"));
    }

    // An envelope sealed to the wrong key is rejected.
    {
        const Key wrong = Key::generateSealing();
        const Bytes sealed = makeSealed(Key::fromPublicDer(wrong.publicDer()), "content", alice,
            "fmsg-3", token);
        const FederationDeliverResult result = roundTrip(engine, sealed, payload);
        CHECK(!result.delivered);
        CHECK(result.errorCode == "DELIVERY_REJECTED");
    }

    // A per-destination serving key (not the home key): an envelope sealed to a
    // destination's own key is delivered when served with that key, and rejected
    // when served with the home key. This is the per-destination unsealing that
    // pool and per-user destinations rely on (see api/InviteAnonymity.md).
    {
        const Key destKey = Key::generateSealing();
        const Bytes sealed
            = makeSealed(Key::fromPublicDer(destKey.publicDer()), "contact", alice, "fdest-1", {});
        CHECK(roundTrip(engine, sealed, Bytes(50, 0x55), &destKey).delivered);
        CHECK(storage.getBlob(alice, "fdest-1").size() == 50);

        const Bytes sealedHome
            = makeSealed(Key::fromPublicDer(destKey.publicDer()), "contact", alice, "fdest-2", {});
        CHECK(!roundTrip(engine, sealedHome, Bytes(50, 0x55)).delivered);
    }

    std::filesystem::remove_all(root);
    return 0;
}
