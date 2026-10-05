// Bazarish project (c) 2026
#include "Federation.hpp"

#include "DeliveryEngine.hpp"
#include "DiskStorage.hpp"

#include <bazarish/Cms.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Resolve.hpp>
#include <bazarish/Pass.hpp>

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
constexpr std::uint64_t kTinyQuotaBytes = 1024;
constexpr std::uint64_t kAmpleQuotaBytes = 50 * 1024 * 1024;

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

    std::size_t readSome(void* const buffer, const std::size_t size)
    {
        const ssize_t got = ::read(fd, buffer, size);
        if (got < 0) {
            throw std::runtime_error("socket read failed");
        }
        return static_cast<std::size_t>(got);
    }

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

Bytes makeSealed(const Key& sealingPublic, const std::string& kind,
    const std::string& mailbox, const std::string& deliveryId, const Bytes& pass)
{
    nlohmann::json inner = {{"class", kind}, {"mailbox", mailbox}, {"deliveryId", deliveryId}};
    if (kind == "content") {
        inner["pass"] = toBase64(pass);
    }
    const std::string text = inner.dump();
    return cms::seal(Bytes(text.begin(), text.end()), sealingPublic);
}

FederationDeliverResult roundTrip(DeliveryEngine& engine, const Bytes& sealed, const Bytes& payload,
    const Key* const servingKey = nullptr, const std::string& owner = std::string(),
    const Key* const ackSigningKey = nullptr)
{
    int fds[2];
    CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    SocketStream serverStream(fds[0]);
    SocketStream clientStream(fds[1]);

    std::thread serverThread([&engine, &serverStream, servingKey, owner, ackSigningKey]() {
        SignAckFn signAck;
        if (ackSigningKey != nullptr) {
            signAck = [ackSigningKey](const std::string& deliveryId, Bytes& outPub, Bytes& outSig) {
                outSig = bazarish::sign(*ackSigningKey, Bytes(deliveryId.begin(), deliveryId.end()));
                outPub = ackSigningKey->publicDer();
            };
        }
        federationServeOnce(serverStream, engine, kNow, std::string(), nullptr, servingKey, owner,
            GetCardFn{}, signAck);
    });
    const FederationDeliverResult result
        = federationSendDeliver(clientStream, sealed, payload);
    serverThread.join();
    return result;
}

FederationFetchResult roundTripCard(DeliveryEngine& engine, const CardFetchQuery& query,
    const GetCardFn& getCard, const std::string& owner = {})
{
    int fds[2];
    CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    SocketStream serverStream(fds[0]);
    SocketStream clientStream(fds[1]);

    std::thread serverThread([&engine, &serverStream, &getCard, &owner]() {
        federationServeOnce(
            serverStream, engine, kNow, std::string(), nullptr, nullptr, owner, getCard);
    });
    const std::string queryText = toJson(query).dump();
    const FederationFetchResult result = federationSendFetch(
        clientStream, "card", Bytes(queryText.begin(), queryText.end()));
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
        std::make_shared<Key>(Key::fromPrivatePem(sealing.privatePem())),
        DeliveryEngineOptions{});

    const Bytes secret = randomBytes(kDeliverySecretSize);
    const Bytes pass = deliveryPass(secret, std::string(52, 'b'));
    storage.registerPasses(alice, {deliveryPassHandle(pass)});

    const Bytes payload = {'f', 'e', 'd', '-', 'b', 'l', 'o', 'b'};

    {
        const Bytes sealed = makeSealed(sealingPublic, "content", alice, "fmsg-1", pass);
        const FederationDeliverResult result = roundTrip(engine, sealed, payload);
        CHECK(result.delivered);
        CHECK(storage.passCount(alice) == 1);
        CHECK(storage.getBlob(alice, "fmsg-1") == payload);
    }

    for (int i = 0; i < 100; ++i) {
        const Bytes sealed = makeSealed(
            sealingPublic, "content", alice, "fmsg-again-" + std::to_string(i), pass);
        CHECK(roundTrip(engine, sealed, payload).delivered);
    }
    CHECK(storage.passCount(alice) == 1);

    {
        const Bytes sealed = makeSealed(sealingPublic, "content", alice, "fmsg-1", pass);
        const FederationDeliverResult result = roundTrip(engine, sealed, payload);
        CHECK(result.delivered);
    }

    {
        const Bytes sealed = makeSealed(sealingPublic, "content", alice, "fmsg-2",
            deliveryPass(randomBytes(kDeliverySecretSize), std::string(52, 'b')));
        const FederationDeliverResult result = roundTrip(engine, sealed, payload);
        CHECK(!result.delivered);
        CHECK(result.errorCode == "DELIVERY_REJECTED");
    }

    {
        const Bytes sealed = makeSealed(sealingPublic, "content", alice, "fmsg-huge", pass);
        const FederationDeliverResult result
            = roundTrip(engine, sealed, Bytes(bazarish::kMaxMessagePayloadBytes + 1, 0x55));
        CHECK(!result.delivered);
        CHECK(result.errorCode == "MESSAGE_TOO_LARGE");
    }

    {
        const Bytes stranger = deliveryPass(randomBytes(kDeliverySecretSize), std::string(52, 'z'));
        const Bytes small
            = makeSealed(sealingPublic, "content", alice, "fmsg-probe-small", stranger);
        const FederationDeliverResult refusedSmall = roundTrip(engine, small, payload);
        const Bytes huge = makeSealed(sealingPublic, "content", alice, "fmsg-probe-huge", stranger);
        const FederationDeliverResult refusedHuge
            = roundTrip(engine, huge, Bytes(bazarish::kMaxMessagePayloadBytes + 1, 0x55));
        CHECK(!refusedSmall.delivered);
        CHECK(!refusedHuge.delivered);
        CHECK(refusedHuge.errorCode == refusedSmall.errorCode);
        CHECK(refusedHuge.errorMessage == refusedSmall.errorMessage);
    }

    {
        const std::string newcomer = toBase32(Bytes(32, 0x66));
        const Bytes sealed = makeSealed(sealingPublic, "contact", newcomer, "freq-big", {});
        const FederationDeliverResult result = roundTrip(engine, sealed,
            Bytes(bazarish::kMaxContactRequestBytes + 1, 0x55), nullptr, newcomer);
        CHECK(!result.delivered);
        CHECK(result.errorCode == "CONTACT_REQUEST_TOO_LARGE");
    }

    {
        storage.setUserQuota(alice, kTinyQuotaBytes);
        const Bytes sealed = makeSealed(sealingPublic, "content", alice, "fmsg-full", pass);
        const FederationDeliverResult result
            = roundTrip(engine, sealed, Bytes(kTinyQuotaBytes * 2, 0x77));
        CHECK(!result.delivered);
        CHECK(result.errorCode == "STORAGE_FULL");
        CHECK(storage.passCount(alice) == 1);
        storage.setUserQuota(alice, kAmpleQuotaBytes);
    }

    {
        const Bytes sealed = makeSealed(sealingPublic, "contact", alice, "freq-1", {});
        const FederationDeliverResult result = roundTrip(engine, sealed, Bytes(100, 0x33));
        CHECK(result.delivered);
        CHECK(storage.getBlob(alice, "freq-1").size() == 100);
    }

    {
        storage.registerClient(alice, "client01");
        const Bytes sealed = makeSealed(sealingPublic, "contact", alice, "freq-replay", {});

        CHECK(roundTrip(engine, sealed, Bytes(100, 0x44)).delivered);
        CHECK(storage.hasBlob(alice, "freq-replay"));

        storage.ackBlob(alice, "freq-replay", "client01");
        CHECK(!storage.hasBlob(alice, "freq-replay"));

        CHECK(roundTrip(engine, sealed, Bytes(100, 0x44)).delivered);
        CHECK(!storage.hasBlob(alice, "freq-replay"));
    }

    {
        const Key wrong = Key::generateSealing();
        const Bytes sealed = makeSealed(Key::fromPublicDer(wrong.publicDer()), "content", alice,
            "fmsg-3", pass);
        const FederationDeliverResult result = roundTrip(engine, sealed, payload);
        CHECK(!result.delivered);
        CHECK(result.errorCode == "DELIVERY_REJECTED");
    }

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

    {
        const std::string stranger = toBase32(Bytes(32, 0x44));
        const Bytes payload(64, 0x41);
        for (std::size_t i = 0; i < bazarish::kContactRequestsPerMinute; ++i) {
            const FederationDeliverResult result = roundTrip(engine,
                makeSealed(sealingPublic, "contact", stranger, "cap-" + std::to_string(i), {}),
                payload, nullptr, stranger);
            CHECK(result.delivered);
        }
        CHECK(storage.listPending(stranger, "dev").size()
            == bazarish::kContactRequestsPerMinute);

        const FederationDeliverResult refused = roundTrip(engine,
            makeSealed(sealingPublic, "contact", stranger, "cap-over", {}), payload, nullptr,
            stranger);
        CHECK(!refused.delivered);
        CHECK(refused.errorCode == "CONTACT_RATE_LIMITED");

        const FederationDeliverResult refusedOther = roundTrip(engine,
            makeSealed(sealingPublic, "contact", toBase32(Bytes(32, 0x55)), "cap-other", {}),
            payload, nullptr, stranger);
        CHECK(!refusedOther.delivered);
        CHECK(refusedOther.errorCode == refused.errorCode);
    }

    {
        const std::string stranger = toBase32(Bytes(32, 0x33));
        const Bytes payload(64, 0x41);
        const Bytes sealedForStranger
            = makeSealed(sealingPublic, "contact", stranger, "wrong-dest", {});
        const FederationDeliverResult answered
            = roundTrip(engine, sealedForStranger, payload, nullptr, alice);
        CHECK(answered.delivered);
        CHECK(storage.listPending(stranger, "dev").empty());
        CHECK(storage.usage(stranger) == 0);

        const FederationDeliverResult real = roundTrip(engine,
            makeSealed(sealingPublic, "contact", stranger, "wrong-dest", {}), payload, nullptr,
            stranger);
        CHECK(real.delivered);
        CHECK(storage.listPending(stranger, "dev").size() == 1);
    }

    {
        const Bytes cardDer(200, 0x5a);
        const std::string view = "0123456789abcdef0123456789abcdef";
        const GetCardFn getCard
            = [&](const std::string& fp, const std::string& asked) -> std::optional<Bytes> {
            if (fp == alice && asked == view) {
                return cardDer;
            }
            return std::nullopt;
        };

        const FederationFetchResult ok = roundTripCard(engine, CardFetchQuery{alice, view}, getCard);
        CHECK(ok.ok);
        CHECK(ok.sealed == cardDer);

        const FederationFetchResult unknown
            = roundTripCard(engine, CardFetchQuery{toBase32(Bytes(32, 0x77)), view}, getCard);
        CHECK(!unknown.ok);
        CHECK(unknown.errorCode == "CARD_UNKNOWN");

        const FederationFetchResult refused = roundTripCard(
            engine, CardFetchQuery{alice, "ffffffffffffffffffffffffffffffff"}, getCard);
        CHECK(!refused.ok);
        CHECK(refused.errorCode == unknown.errorCode);

        const FederationFetchResult noFn
            = roundTripCard(engine, CardFetchQuery{alice, view}, GetCardFn{});
        CHECK(!noFn.ok);
        CHECK(noFn.errorCode == "CARD_UNKNOWN");

        const std::string bob = toBase32(Bytes(32, 0x0b));
        const GetCardFn nodeWide
            = [&](const std::string& fp, const std::string& asked) -> std::optional<Bytes> {
            if ((fp == alice || fp == bob) && asked == view) {
                return cardDer;
            }
            return std::nullopt;
        };
        const FederationFetchResult own
            = roundTripCard(engine, CardFetchQuery{alice, view}, nodeWide, alice);
        CHECK(own.ok);
        CHECK(own.sealed == cardDer);

        const FederationFetchResult neighbour
            = roundTripCard(engine, CardFetchQuery{bob, view}, nodeWide, alice);
        CHECK(!neighbour.ok);
        CHECK(neighbour.errorCode == "CARD_UNKNOWN");
        const FederationFetchResult absent = roundTripCard(
            engine, CardFetchQuery{toBase32(Bytes(32, 0x99)), view}, nodeWide, alice);
        CHECK(absent.errorCode == neighbour.errorCode);
    }

    {
        const Key ackKey = Key::generateSigning();
        const Bytes sealed = makeSealed(sealingPublic, "content", alice, "fmsg-signed", pass);
        const FederationDeliverResult result
            = roundTrip(engine, sealed, payload, nullptr, std::string(), &ackKey);
        CHECK(result.delivered);
        CHECK(result.deliveryId == "fmsg-signed");
        CHECK(!result.signature.empty());
        const Bytes signedBytes(result.deliveryId.begin(), result.deliveryId.end());
        CHECK(bazarish::verify(
            Key::fromPublicDer(result.signerPublicDer), signedBytes, result.signature));
        const Key other = Key::generateSigning();
        CHECK(!bazarish::verify(Key::fromPublicDer(other.publicDer()), signedBytes,
            result.signature));
    }

    {
        const Bytes sealed = makeSealed(sealingPublic, "content", alice, "fmsg-unsigned", pass);
        const FederationDeliverResult result = roundTrip(engine, sealed, payload);
        CHECK(result.delivered);
        CHECK(result.signature.empty());
    }

    {
        int fds[2];
        CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
        SocketStream serverStream(fds[0]);
        SocketStream clientStream(fds[1]);
        std::thread serverThread([&engine, &serverStream]() {
            federationServeOnce(serverStream, engine, kNow);
        });
        const std::string truncated = "{\"op\":\"deli";
        CHECK(::write(fds[1], truncated.data(), truncated.size())
            == static_cast<ssize_t>(truncated.size()));
        CHECK(::shutdown(fds[1], SHUT_WR) == 0);
        std::string answer;
        char byte = 0;
        while (::read(fds[1], &byte, 1) == 1 && byte != '\n') {
            answer.push_back(byte);
        }
        serverThread.join();
        CHECK(!answer.empty());
        CHECK(answer.find("DELIVERY_REJECTED") != std::string::npos);
    }

    std::filesystem::remove_all(root);
    return 0;
}
