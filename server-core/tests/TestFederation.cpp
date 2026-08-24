// Bazarish project (c) 2026
#include "Federation.hpp"

#include "DeliveryEngine.hpp"
#include "DiskStorage.hpp"

#include <bazarish/Cms.hpp>
#include <bazarish/Resolve.hpp>
#include <bazarish/Tokens.hpp>

#include <nlohmann/json.hpp>

#include <sys/socket.h>
#include <unistd.h>

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <optional>
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

using namespace bazarish;
using namespace bazarish::server;

namespace {

constexpr std::int64_t kNow = 1780000000;

// A minimal fd-backed stream exposing the readExact/writeAll surface the
// federation framing templates over - stands in for a bazarish::i2p::Stream so
// the protocol can be socketpair-tested without a router.
struct SocketStream {
    int fd;
    explicit SocketStream(int f) : fd(f) {}
    ~SocketStream()
    {
        if (fd >= 0) {
            ::close(fd);
        }
    }
    SocketStream(const SocketStream&) = delete;
    SocketStream& operator=(const SocketStream&) = delete;

    void readExact(void* buffer, std::size_t size)
    {
        auto* p = static_cast<char*>(buffer);
        std::size_t got = 0;
        while (got < size) {
            const ssize_t r = ::read(fd, p + got, size - got);
            if (r <= 0) {
                throw std::runtime_error("short read");
            }
            got += static_cast<std::size_t>(r);
        }
    }
    void writeAll(const void* data, std::size_t size)
    {
        const auto* p = static_cast<const char*>(data);
        std::size_t off = 0;
        while (off < size) {
            const ssize_t w = ::write(fd, p + off, size - off);
            if (w < 0) {
                throw std::runtime_error("write error");
            }
            off += static_cast<std::size_t>(w);
        }
    }
};

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

// Runs one client deliver against an in-thread server using a socketpair -
// the same SocketStream wraps both ends, so the federation protocol is
// exercised without I2P.
FederationDeliverResult roundTrip(DeliveryEngine& engine, const Bytes& sealed, const Bytes& payload,
    const Key* const servingKey = nullptr, const std::string& owner = std::string())
{
    int fds[2];
    CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    SocketStream serverStream(fds[0]);
    SocketStream clientStream(fds[1]);

    std::thread serverThread([&engine, &serverStream, servingKey, owner]() {
        federationServeOnce(serverStream, engine, kNow, std::string(), nullptr, servingKey, owner);
    });
    const FederationDeliverResult result
        = federationSendDeliver(clientStream, sealed, payload);
    serverThread.join();
    return result;
}

// Runs one client card fetch against an in-thread server (socketpair), with a
// stub card lookup. servingKey == nullptr uses the engine's home sealing key.
FederationFetchResult roundTripCard(DeliveryEngine& engine, const Bytes& sealedQuery,
    const Key* const servingKey, const GetCardFn& getCard)
{
    int fds[2];
    CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    SocketStream serverStream(fds[0]);
    SocketStream clientStream(fds[1]);

    std::thread serverThread([&engine, &serverStream, servingKey, &getCard]() {
        federationServeOnce(serverStream, engine, kNow, std::string(), nullptr, servingKey,
            std::string(), getCard);
    });
    const FederationFetchResult result = federationSendFetch(clientStream, "card", sealedQuery);
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

    // A destination belongs to one user, and only their mail belongs in it.
    // Mail for anyone else is answered exactly like a delivered one - refusing
    // would say whose destination this is - and stored nowhere. The seen-cache
    // must not be touched either, or delivering a real messageId to the wrong
    // destination first would censor it at the right one.
    {
        const std::string stranger = toBase32(Bytes(32, 0x33));
        const Bytes payload(64, 0x41);
        const Bytes sealedForStranger
            = makeSealed(sealingPublic, "contact", stranger, "wrong-dest", {});
        const FederationDeliverResult answered
            = roundTrip(engine, sealedForStranger, payload, nullptr, alice);
        CHECK(answered.delivered);  // says nothing
        CHECK(storage.listPending(stranger, "dev").empty());
        CHECK(storage.usage(stranger) == 0);

        // The same id delivered to its own destination still lands: nothing was
        // marked seen by the drop above.
        const FederationDeliverResult real = roundTrip(engine,
            makeSealed(sealingPublic, "contact", stranger, "wrong-dest", {}), payload, nullptr,
            stranger);
        CHECK(real.delivered);
        CHECK(storage.listPending(stranger, "dev").size() == 1);
    }

    // Card fetch: a query sealed to the server's serving key returns the user's
    // contact card sealed to the query's ephemeral response key.
    {
        const Key ephemeral = Key::generateSealing();
        const Bytes cardDer(200, 0x5a);  // opaque contact card
        const Bytes servingKey{0x11, 0x22, 0x33};
        // The lookup answers only for the key it issued, and says the same
        // nothing for a wrong key as for a user it does not have.
        const GetCardFn getCard
            = [&](const std::string& fp, const Bytes& keyDer) -> std::optional<Bytes> {
            if (fp == alice && keyDer == servingKey) {
                return cardDer;
            }
            return std::nullopt;
        };

        const CardFetchQuery query{alice, servingKey, ephemeral.publicDer()};
        const std::string queryJson = toJson(query).dump();
        const Bytes sealedQuery = cms::seal(Bytes(queryJson.begin(), queryJson.end()), sealingPublic);

        const FederationFetchResult ok = roundTripCard(engine, sealedQuery, nullptr, getCard);
        CHECK(ok.ok);
        const CardFetchResponse resp
            = cardFetchResponseFromJson(nlohmann::json::parse(cms::unseal(ok.sealed, ephemeral)));
        CHECK(resp.cardDer == cardDer);

        // An unknown user collapses into CARD_UNKNOWN.
        const CardFetchQuery missing{toBase32(Bytes(32, 0x77)), servingKey, ephemeral.publicDer()};
        const std::string missingJson = toJson(missing).dump();
        const Bytes sealedMissing
            = cms::seal(Bytes(missingJson.begin(), missingJson.end()), sealingPublic);
        const FederationFetchResult unknown = roundTripCard(engine, sealedMissing, nullptr, getCard);
        CHECK(!unknown.ok);
        CHECK(unknown.errorCode == "CARD_UNKNOWN");

        // A right user with the wrong key is refused exactly the same way, so
        // asking teaches nothing about who is served here.
        const CardFetchQuery wrongKey{alice, Bytes{0x99}, ephemeral.publicDer()};
        const std::string wrongJson = toJson(wrongKey).dump();
        const Bytes sealedWrong = cms::seal(Bytes(wrongJson.begin(), wrongJson.end()), sealingPublic);
        const FederationFetchResult refused = roundTripCard(engine, sealedWrong, nullptr, getCard);
        CHECK(!refused.ok);
        CHECK(refused.errorCode == unknown.errorCode);

        // No card lookup wired -> CARD_UNKNOWN.
        const FederationFetchResult noFn = roundTripCard(engine, sealedQuery, nullptr, GetCardFn{});
        CHECK(!noFn.ok);
        CHECK(noFn.errorCode == "CARD_UNKNOWN");
    }

    std::filesystem::remove_all(root);
    return 0;
}
