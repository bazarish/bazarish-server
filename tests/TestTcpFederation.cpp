// Bazarish project (c) 2026
#include "TcpFederation.hpp"

#include "DeliveryEngine.hpp"
#include "DiskStorage.hpp"

#include <bazarish/Cms.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Tokens.hpp>

#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <optional>
#include <string>

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

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-tcpfed-test";
    std::filesystem::remove_all(root);
    DiskStorage storage(root);

    // The receiving server: its sealing key reads the envelope metadata.
    const Key serverSealing = Key::generateSealing();
    DeliveryEngine engine(storage, "server-b-fingerprint",
        Key::fromPrivatePem(serverSealing.privatePem()), DeliveryEngineOptions{});

    // A recipient mailbox with one registered delivery token.
    const Identity recipient = Identity::generate();
    const std::string mailbox = recipient.fingerprint();
    const Bytes token = generateDeliveryToken();
    storage.registerTokenHashes(mailbox, {deliveryTokenHash(token)});

    int boundPort = 0;
    const TcpFederation::Resolver resolver
        = [&boundPort](const std::string& serverFp) -> std::optional<std::string> {
        if (serverFp == "server-b") {
            return std::string("127.0.0.1:") + std::to_string(boundPort);
        }
        return std::nullopt;
    };

    TcpFederation federation(engine, resolver);
    boundPort = federation.bindAndListen("127.0.0.1", 0);
    CHECK(boundPort > 0);
    federation.start();

    // Build a sealed delivery envelope addressed to the receiving server.
    const std::string messageId = "fedmsg0001";
    const nlohmann::json inner = {
        {"kind", "message"},
        {"mailbox", mailbox},
        {"messageId", messageId},
        {"token", toBase64(token)},
    };
    const std::string innerText = inner.dump();
    const Bytes sealed = cms::seal(Bytes(innerText.begin(), innerText.end()),
        Key::fromPublicDer(serverSealing.publicDer()));
    const Bytes payload = {0x41, 0x42, 0x43};

    // A reachable server delivers and stores the blob in the mailbox.
    {
        const RemoteDeliveryResult result = federation.deliver("server-b", sealed, payload);
        CHECK(result.reachable);
        CHECK(result.delivered);
        CHECK(storage.hasBlob(mailbox, messageId));
        CHECK(storage.getBlob(mailbox, messageId) == payload);
    }

    // A retry with the same messageId is idempotent (dedup, no second token).
    {
        const RemoteDeliveryResult result = federation.deliver("server-b", sealed, payload);
        CHECK(result.reachable);
        CHECK(result.delivered);
    }

    // An unresolvable server is reported unreachable, not delivered.
    {
        const RemoteDeliveryResult result = federation.deliver("server-x", sealed, payload);
        CHECK(!result.reachable);
        CHECK(!result.delivered);
    }

    federation.stop();
    std::filesystem::remove_all(root);
    std::fprintf(stderr, "TestTcpFederation passed\n");
    return 0;
}
