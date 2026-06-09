// Bazarish project (c) 2026
#include "DeliveryEngine.hpp"
#include "DiskStorage.hpp"
#include "Federation.hpp"

#include <bazarish/Cms.hpp>
#include <bazarish/Sam.hpp>
#include <bazarish/Tokens.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <optional>
#include <string>
#include <thread>

// Live two-node federation smoke against a local i2pd SAM bridge. Builds two
// I2P STREAM sessions (sender and recipient), delivers one sealed message
// from sender to recipient over real I2P and verifies it landed. Not part of
// the gating test suite: it depends on tunnel build, which is slow and
// network-dependent.
using namespace bazarish;
using namespace bazarish::server;

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-i2p-smoke";
    std::filesystem::remove_all(root);
    DiskStorage storage(root);

    const std::string alice = toBase32(Bytes(32, 0x01));
    const Key sealing = Key::generateSealing();
    const Key sealingPublic = Key::fromPublicDer(sealing.publicDer());
    DeliveryEngine engine(storage, toBase32(Bytes(32, 0xee)),
        Key::fromPrivatePem(sealing.privatePem()), DeliveryEngineOptions{});

    const Bytes token = generateDeliveryToken();
    storage.registerTokenHashes(alice, {deliveryTokenHash(token)});

    std::printf("creating recipient SAM session (building tunnels)...\n");
    std::fflush(stdout);
    SamSession recipient(SamClient::kDefaultHost, SamClient::kDefaultPort, "bazarish-recv");
    std::printf("recipient destination: %s...\n", recipient.publicDestination().substr(0, 24).c_str());

    std::printf("creating sender SAM session...\n");
    std::fflush(stdout);
    SamSession sender(SamClient::kDefaultHost, SamClient::kDefaultPort, "bazarish-send");

    const auto now = static_cast<std::int64_t>(std::time(nullptr));

    // Recipient accepts one inbound stream and serves the delivery.
    std::string recipientError;
    std::thread serverThread([&recipient, &engine, now, &recipientError]() {
        try {
            std::string peer;
            SamStream stream = recipient.accept(peer);
            std::printf("recipient: accepted peer %s...\n", peer.substr(0, 24).c_str());
            std::fflush(stdout);
            federationServeOnce(stream, engine, now);
            std::printf("recipient: served delivery\n");
            std::fflush(stdout);
        } catch (const std::exception& error) {
            recipientError = error.what();
        }
    });

    nlohmann::json inner = {
        {"kind", "message"}, {"mailbox", alice}, {"messageId", "i2p-1"},
        {"token", toBase64(token)}};
    const std::string innerText = inner.dump();
    const Bytes sealed = cms::seal(Bytes(innerText.begin(), innerText.end()), sealingPublic);
    const Bytes payload = {'o', 'v', 'e', 'r', '-', 'i', '2', 'p'};

    // A freshly created destination needs time to publish its leaseset to
    // the netDB before peers can look it up; CANT_REACH_PEER / "LeaseSet
    // not found" right after creation just means we were early. Retry.
    std::printf("waiting for recipient leaseset to publish...\n");
    std::fflush(stdout);
    std::this_thread::sleep_for(std::chrono::seconds(20));

    std::optional<SamStream> stream;
    for (int attempt = 1; attempt <= 8 && !stream.has_value(); ++attempt) {
        try {
            std::printf("connecting sender -> recipient over I2P (attempt %d)...\n", attempt);
            std::fflush(stdout);
            stream.emplace(sender.connect(recipient.publicDestination()));
        } catch (const std::exception& error) {
            std::printf("  connect attempt %d failed: %s\n", attempt, error.what());
            std::fflush(stdout);
            std::this_thread::sleep_for(std::chrono::seconds(15));
        }
    }
    if (!stream.has_value()) {
        std::fprintf(stderr, "could not reach recipient over I2P after retries\n");
        return 1;
    }
    std::optional<FederationDeliverResult> result;
    std::string senderError;
    try {
        result = federationSendDeliver(stream.value(), sealed, payload);
    } catch (const std::exception& error) {
        senderError = error.what();
    }
    serverThread.join();

    if (!recipientError.empty()) {
        std::fprintf(stderr, "recipient side failed: %s\n", recipientError.c_str());
    }
    if (!senderError.empty()) {
        std::fprintf(stderr, "sender side failed: %s\n", senderError.c_str());
    }
    if (!result.has_value() || !recipientError.empty() || !senderError.empty()) {
        return 1;
    }
    if (!result->delivered) {
        std::fprintf(stderr, "delivery failed: %s %s\n", result->errorCode.c_str(),
            result->errorMessage.c_str());
        return 1;
    }
    if (storage.getBlob(alice, "i2p-1") != payload) {
        std::fprintf(stderr, "blob mismatch after I2P delivery\n");
        return 1;
    }
    std::printf("OK: message delivered to mailbox over real I2P, token consumed (%zu left)\n",
        storage.tokenHashCount(alice));
    std::filesystem::remove_all(root);
    return 0;
}
