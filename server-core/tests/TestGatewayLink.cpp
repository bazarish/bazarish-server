// Bazarish project (c) 2026
#include "GatewayLink.hpp"

#include "DeliveryEngine.hpp"
#include "DiskStorage.hpp"
#include "PerUserDestinations.hpp"

#include <TlsPipe.hpp>

#include <bazarish/Crypto.hpp>
#include <bazarish/FederationFrame.hpp>
#include <bazarish/Hybrid.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Tls.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

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
namespace fs = std::filesystem;

namespace {

constexpr std::chrono::seconds kDeadline{5};
constexpr std::size_t kLineBytes = 64 * 1024;
constexpr int kDelegationDays = 1;
constexpr int kRandomNameBytes = 8;
constexpr std::size_t kAccountIdBytes = 32;

const std::string kWatch = nlohmann::json({{"watch", true}}).dump() + "\n";

Bytes contactRequest(const Key& servingPublic, const std::string& mailbox, const std::string& id)
{
    const std::string text
        = nlohmann::json({{"class", "contact"}, {"mailbox", mailbox}, {"deliveryId", id}}).dump();
    return hybrid::seal(Bytes(text.begin(), text.end()), servingPublic);
}

std::vector<std::string> listed(TlsPipe& pipe)
{
    const nlohmann::json line = nlohmann::json::parse(pipe.readLine(kLineBytes));
    std::vector<std::string> dests;
    for (const nlohmann::json& dest : line.at("dests")) {
        dests.push_back(dest.get<std::string>());
    }
    std::sort(dests.begin(), dests.end());
    return dests;
}

std::unique_ptr<TlsPipe> streamTo(const int port, const tls::Credential& server,
    const tls::Credential& gateway, const std::string& to, const std::string& from)
{
    std::unique_ptr<TlsPipe> pipe
        = TlsPipe::dial("127.0.0.1", port, server.pin, kDeadline, &gateway);
    const std::string preface = nlohmann::json({{"to", to}, {"from", from}}).dump() + "\n";
    pipe->writeAll(preface.data(), preface.size());
    return pipe;
}

class Sender {
public:
    explicit Sender(TlsPipe& pipe)
        : pipe_(pipe)
    {
    }

    std::size_t readSome(void* buffer, const std::size_t size)
    {
        return pipe_.readSome(buffer, size);
    }

    void readExact(void* buffer, const std::size_t size)
    {
        auto* const at = static_cast<unsigned char*>(buffer);
        std::size_t done = 0;
        while (done < size) {
            const std::size_t got = pipe_.readSome(at + done, size - done);
            if (got == 0) {
                throw std::runtime_error("the server ended the stream early");
            }
            done += got;
        }
    }

    void writeAll(const void* data, const std::size_t size) { pipe_.writeAll(data, size); }

private:
    TlsPipe& pipe_;
};

FederationDeliverResult deliver(TlsPipe& pipe, const Bytes& sealed, const Bytes& payload)
{
    Sender sender(pipe);
    return federationSendDeliver(sender, sealed, payload);
}

bool answeredOk(TlsPipe& pipe)
{
    return nlohmann::json::parse(pipe.readLine(kLineBytes)).value("ok", false);
}

bool cutOff(TlsPipe& pipe)
{
    try {
        (void)pipe.readLine(kLineBytes);
    } catch (const std::exception&) {
        return true;
    }
    return false;
}

}  // namespace

int main()
{
    const fs::path root = fs::temp_directory_path()
        / ("bazarish-gateway-link-" + toHex(randomBytes(kRandomNameBytes)));
    DiskStorage storage(root / "storage");
    const Key sealing = Key::generateSealing();
    DeliveryEngine engine(storage, toBase32(Bytes(kAccountIdBytes, 0xee)),
        std::make_shared<Key>(Key::fromPrivatePem(sealing.privatePem())),
        DeliveryEngineOptions{});
    PerUserDestinations dests(nullptr, engine, root / "dests", i2p::Privacy::eMinimal);

    const tls::Credential server = tls::selfSigned(root / "server");
    const tls::Credential gateway = tls::selfSigned(root / "gateway");
    const tls::Credential stranger = tls::selfSigned(root / "stranger");

    GatewayLink link(
        server, {gateway.pin}, [&dests]() { return dests.served(); },
        [&dests](const std::string& to, const std::string& from, TlsPipe& pipe) {
            return dests.serveDirect(to, from, pipe);
        });
    dests.setServedChanged([&link]() { link.servedChanged(); });
    const int port = link.start("127.0.0.1", 0);
    CHECK(port > 0);

    const std::string alice = toBase32(Bytes(kAccountIdBytes, 0x01));
    const std::string bob = toBase32(Bytes(kAccountIdBytes, 0x02));
    const i2p::Keys aliceKeys = i2p::Keys::generate().issueTransient(kDelegationDays);
    const i2p::Keys bobKeys = i2p::Keys::generate().issueTransient(kDelegationDays);
    const PerUserDestinations::Assignment aliceServed
        = dests.provision(alice, toBase64(aliceKeys.blob()), aliceKeys.transientExpires());

    {
        const std::unique_ptr<TlsPipe> refused
            = TlsPipe::dial("127.0.0.1", port, server.pin, kDeadline, &stranger);
        refused->writeAll(kWatch.data(), kWatch.size());
        CHECK(cutOff(*refused));
    }

    const std::unique_ptr<TlsPipe> watch
        = TlsPipe::dial("127.0.0.1", port, server.pin, kDeadline, &gateway);
    watch->writeAll(kWatch.data(), kWatch.size());
    CHECK(listed(*watch) == std::vector<std::string>{aliceServed.dest});

    const PerUserDestinations::Assignment bobServed
        = dests.provision(bob, toBase64(bobKeys.blob()), bobKeys.transientExpires());
    std::vector<std::string> both{aliceServed.dest, bobServed.dest};
    std::sort(both.begin(), both.end());
    CHECK(listed(*watch) == both);
    dests.revoke(bob);
    CHECK(listed(*watch) == std::vector<std::string>{aliceServed.dest});

    {
        const std::unique_ptr<TlsPipe> gone
            = streamTo(port, server, gateway, bobServed.dest, "first-sender");
        CHECK(!answeredOk(*gone));
    }

    const Key servingPublic = Key::fromPublicDer(aliceServed.sealingKey->publicDer());
    const Bytes payload(kAccountIdBytes, 0x55);
    {
        const std::unique_ptr<TlsPipe> first
            = streamTo(port, server, gateway, aliceServed.dest, "first-sender");
        CHECK(answeredOk(*first));
        CHECK(deliver(*first, contactRequest(servingPublic, alice, "via-gateway-1"), payload)
                  .delivered);
    }
    {
        const std::unique_ptr<TlsPipe> again
            = streamTo(port, server, gateway, aliceServed.dest, "first-sender");
        CHECK(answeredOk(*again));
        const FederationDeliverResult limited
            = deliver(*again, contactRequest(servingPublic, alice, "via-gateway-2"), payload);
        CHECK(!limited.delivered);
        CHECK(limited.errorCode == "CONTACT_RATE_LIMITED");
    }
    {
        const std::unique_ptr<TlsPipe> other
            = streamTo(port, server, gateway, aliceServed.dest, "second-sender");
        CHECK(answeredOk(*other));
        CHECK(deliver(*other, contactRequest(servingPublic, alice, "via-gateway-2"), payload)
                  .delivered);
    }

    link.setGateways({});
    CHECK(cutOff(*watch));

    link.stop();
    fs::remove_all(root);
    std::printf("TestGatewayLink: all checks passed\n");
    return 0;
}
