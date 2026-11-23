// Bazarish project (c) 2026
#include "NodeCards.hpp"
#include "DeviceTestKit.hpp"
#include "TestUtil.hpp"

#include <ServiceRoutes.hpp>

#include <bazarish/Certificates.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/Epochs.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/KeyedSeal.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Tls.hpp>

#include <nlohmann/json.hpp>

#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>

using namespace bazarish;
using namespace bazarish::server;

namespace {

const std::string kCardDest = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p";

Bytes cardOf(const devicetest::Account& owner)
{
    const std::int64_t issuedAt = nowSeconds();
    ContactCard card;
    card.kind = AccountKind::eUser;
    card.issuedAt = issuedAt;
    card.dest = kCardDest;
    const EpochNumber current = epochAt(issuedAt);
    card.epochs = {{current, kFirstEpochGeneration, owner.keys.id(), Key::generateSealing().publicDer()},
        {current + 1, kFirstEpochGeneration, owner.keys.id(), Key::generateSealing().publicDer()}};
    card.servingSealingKeyDer = Key::generateSealing().publicDer();
    return card.issue(owner.root);
}

}  // namespace

int main()
try {
    bazarish::log::setLevel(bazarish::log::Level::eError);
    const testutil::ScratchDir scratch("node-cards-test");
    const std::filesystem::path& root = scratch.path();
    const tls::Credential credential = tls::selfSigned(root);
    const auto identity = std::make_shared<const Identity>(Identity::generate());

    CHECK_THROWS(NodeCards(NodeAddress{"127.0.0.1", 1, false, credential.pin}, identity));
    CHECK_THROWS(NodeCards(NodeAddress{"127.0.0.1", 1, true, {}}, identity));

    const devicetest::Account alice;
    const devicetest::Account mallory;
    const Bytes aliceCard = cardOf(alice);
    const Bytes malloryCard = cardOf(mallory);

    http::Server::Options options;
    options.port = 0;
    options.threads = 1;
    options.certificate = credential.certificate.string();
    options.key = credential.key.string();
    http::Server node(options);
    node.get(routes::kAccountCard, [&](const http::Request& request) {
        const std::string user = request.query("user");
        const Bytes& card = user == alice.fingerprint() ? malloryCard : aliceCard;
        http::Response response;
        response.contentType = "application/json";
        response.body = nlohmann::json{{"user", user}, {"card", toBase64(card)},
            {"cardKey", linkKeyText(newLinkKey())}}.dump();
        return response;
    });
    const int port = node.start();
    CHECK(port > 0);

    NodeCards cards(NodeAddress{"127.0.0.1", port, true, credential.pin}, identity);
    CHECK_THROWS(cards.card(alice.fingerprint()));
    CHECK_THROWS(cards.card(mallory.fingerprint()));

    node.stop();
    std::printf("TestNodeCards OK\n");
    return 0;
} catch (...) {
    return testutil::failed();
}
