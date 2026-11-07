// Bazarish project (c) 2026
#include "DeliveryEngine.hpp"
#include "DiskStorage.hpp"
#include "EventGate.hpp"
#include "GatewayLink.hpp"
#include "HttpApi.hpp"
#include "NodeCards.hpp"
#include "PerUserDestinations.hpp"

#include <BuildVersion.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/ConfigFile.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/PrivateFile.hpp>
#include <bazarish/Tls.hpp>
#include <Restart.hpp>
#include <StateIdentity.hpp>

#include <bazarish/HttpClient.hpp>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>

namespace {

namespace fs = std::filesystem;

constexpr const char* kDefaultHost = "127.0.0.1";
constexpr int kDefaultPort = 8420;
constexpr int kDefaultOpsPort = 8428;

void printUsage()
{
    std::printf(
        "bazarish-server %s\n"
        "Usage: bazarish-server --config <path>\n"
        "       bazarish-server --version\n"
        "\n"
        "Everything this server runs on is in the config file - state directory,\n"
        "listen addresses, operator fingerprints, I2P settings - so there is\n"
        "one place to look and one place to change. The state directory holds the\n"
        "server keys and the content storage; keys are generated on first start,\n"
        "and the server card is always written to <state>/server-card.der.\n"
        "\n"
        "The server keeps no destination of its own: inbound federation arrives on\n"
        "each user's own I2P destination, which it operates from the transient that\n"
        "user delegated to it. Clients reach this server through a facade.\n",
        bazarish::kBuildVersion);
}

using bazarish::nowSeconds;
using bazarish::readFileText;
using bazarish::writePrivateFile;

}  // namespace

int main(const int argc, const char** argv)
{
    if (argc == 2 && std::strcmp(argv[1], "--version") == 0) {
        std::printf("bazarish-server %s\n", bazarish::kBuildVersion);
        return 0;
    }
    if (argc != 3 || std::strcmp(argv[1], "--config") != 0) {
        printUsage();
        return 2;
    }

    bazarish::ConfigView config(nlohmann::json::object());
    try {
        config = bazarish::ConfigView(bazarish::ConfigFile(fs::path(argv[2])).read());
    } catch (const std::exception& error) {
        std::fprintf(stderr, "config: %s\n", error.what());
        return 2;
    }

    const fs::path stateDir(config.text("state"));
    if (stateDir.empty()) {
        std::fprintf(stderr, "config: \"state\" is required\n");
        return 2;
    }
    const bazarish::ConfigView::Endpoint listen
        = config.endpoint("listen").value_or(bazarish::ConfigView::Endpoint{kDefaultHost,
            kDefaultPort});
    const std::string host = listen.host;
    const int port = listen.port;
    const bazarish::ConfigView::Endpoint opsListen
        = config.endpoint("opsListen").value_or(bazarish::ConfigView::Endpoint{kDefaultHost,
            kDefaultOpsPort});
    bazarish::server::DeliveryEngineOptions engineOptions;
    const std::vector<std::string> operatorFingerprints = config.list("operators");
    const std::string serviceNodeUrl = config.text("serviceNode.url");
    const std::string serviceNodePin = config.text("serviceNode.pin");
    if (serviceNodeUrl.empty() || serviceNodePin.empty()) {
        std::fprintf(stderr, "config: serviceNode.url and serviceNode.pin are required\n");
        return 1;
    }
    const std::vector<std::string> opsClientPins = config.list("opsClients");
    const std::optional<bazarish::ConfigView::Endpoint> gatewayListen
        = config.endpoint("gatewayListen");
    const std::vector<std::string> gatewayPins = config.list("gateways");
    bazarish::i2p::Privacy privacy = bazarish::i2p::Privacy::eMax;
    if (const std::string named = config.text("i2p.privacy"); !named.empty()) {
        const std::optional<bazarish::i2p::Privacy> parsed
            = bazarish::i2p::privacyFromString(named);
        if (!parsed.has_value()) {
            std::fprintf(stderr, "config: i2p.privacy is not a privacy level\n");
            return 2;
        }
        privacy = *parsed;
    }
    bazarish::log::Level logLevel = bazarish::log::Level::eInfo;
    if (const std::string level = config.text("logLevel"); !level.empty()) {
        const std::optional<bazarish::log::Level> parsed = bazarish::log::levelFromString(level);
        if (!parsed.has_value()) {
            std::fprintf(stderr, "config: logLevel is not a level\n");
            return 2;
        }
        logLevel = *parsed;
    }
    const bool i2pLog = config.flag("i2p.log", false);

    bazarish::log::setComponent("server-core");
    bazarish::log::setLevel(logLevel);
    if (i2pLog) {
        bazarish::i2p::setI2pLogging(true);
    }

    fs::create_directories(stateDir);
    const auto identity = std::make_shared<const bazarish::Identity>(
        bazarish::server::loadOrCreateIdentity(stateDir));
    const auto sealing = std::make_shared<bazarish::Key>(bazarish::server::loadOrCreateSealingKey(stateDir));

    bazarish::server::DiskStorage storage(stateDir / "storage");
    bazarish::server::EventGate eventGate;
    engineOptions.onDelivered = [&eventGate](const std::string& user) { eventGate.notify(user); };
    bazarish::server::DeliveryEngine engine(storage, engineOptions);

    const bazarish::tls::Credential credential = bazarish::tls::selfSigned(stateDir);
    std::printf("bazarish-server %s\n", bazarish::kBuildVersion);
    std::printf("server fingerprint: %s\n", identity->fingerprint().c_str());
    std::printf("server socket pin: %s\n", credential.pin.c_str());
    std::fflush(stdout);

    const bazarish::http::Url serviceNode = bazarish::http::parseUrl(serviceNodeUrl);
    bazarish::server::NodeCards nodeCards(
        {serviceNode.host, serviceNode.port, serviceNode.tls, serviceNodePin}, identity);

    std::unique_ptr<bazarish::i2p::Router> router;
    std::unique_ptr<bazarish::server::PerUserDestinations> perUserDests;
    std::unique_ptr<bazarish::server::GatewayLink> gatewayLink;
    if (gatewayListen.has_value()) {
        gatewayLink = std::make_unique<bazarish::server::GatewayLink>(credential, gatewayPins,
            [&perUserDests]() { return perUserDests->served(); },
            [&perUserDests](const std::string& to, const std::string& from,
                bazarish::server::TlsPipe& pipe) {
                return perUserDests->serveDirect(to, from, pipe);
            });
    }
    {
        bazarish::log::info("starting embedded I2P router (building tunnels)...");
        bazarish::i2p::RouterConfig routerConfig;
        routerConfig.dataDir = stateDir / "i2p";
        routerConfig.role = bazarish::i2p::Role::eServer;
        router = std::make_unique<bazarish::i2p::Router>(routerConfig);

        perUserDests = std::make_unique<bazarish::server::PerUserDestinations>(
            router.get(), engine, stateDir, privacy);
        perUserDests->setGetCard(
            [&nodeCards](const std::string& user) { return nodeCards.card(user); });
        if (gatewayLink) {
            perUserDests->setServedChanged(
                [link = gatewayLink.get()]() { link->servedChanged(); });
        }
        perUserDests->reloadPersisted(nowSeconds());
    }

    const bazarish::Bytes card = bazarish::ServerCard::issue(*identity,
        bazarish::ServerCard::Service::eMessaging,
        bazarish::Key::fromPublicDer(sealing->publicDer()), nowSeconds());
    {
        const fs::path cardPath = stateDir / "server-card.der";
        std::ofstream out(cardPath, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(card.data()),
            static_cast<std::streamsize>(card.size()));
        out.close();
        if (!out) {
            std::fprintf(stderr, "cannot write %s\n", cardPath.string().c_str());
            return 1;
        }
    }

    bazarish::server::HttpApiOptions httpOptions;
    httpOptions.operatorFingerprints = operatorFingerprints;
    httpOptions.version = bazarish::kBuildVersion;
    httpOptions.eventGate = &eventGate;
    httpOptions.defaultQuotaBytes = engineOptions.defaultQuotaBytes;
    httpOptions.reseedSample
        = [](const std::size_t count) { return bazarish::i2p::sampleRouterInfos(count); };
    httpOptions.diskUsage = [stateDir]() {
        std::uint64_t used = 0;
        std::error_code failure;
        for (const fs::directory_entry& entry :
            fs::recursive_directory_iterator(stateDir, failure)) {
            if (entry.is_regular_file(failure)) {
                used += entry.file_size(failure);
            }
        }
        if (failure) {
            bazarish::log::warn("storage walk incomplete: {}", failure.message());
        }
        return used;
    };
    httpOptions.assignDestination
        = [&perUserDests](const std::string& user) -> bazarish::server::DestinationAssignment {
        const bazarish::server::PerUserDestinations::Assignment assigned
            = perUserDests->assignmentFor(user, nowSeconds());
        return {assigned.dest, assigned.state};
    };
    {
        httpOptions.provisionI2pDest = [&perUserDests](const std::string& user,
                                           const std::string& transientB64,
                                           const std::int64_t expiresUnix,
                                           const std::string& sealingKeyPem,
                                           const std::string& signingKeyPem)
            -> bazarish::server::DestinationAssignment {
            const bazarish::server::PerUserDestinations::Assignment served = perUserDests->provision(
                user, transientB64, expiresUnix, sealingKeyPem, signingKeyPem);
            return {served.dest, served.state};
        };
        httpOptions.forgetI2pDest = [&perUserDests, &nodeCards](const std::string& user) {
            nodeCards.forget(user);
            perUserDests->forget(user);
        };
        httpOptions.accountKnown = [&nodeCards](const std::string& user) {
            return nodeCards.card(user).has_value();
        };
    }
    bazarish::server::ServerSettings::Values settingValues;
    settingValues.logLevel = config.text("logLevel").empty() ? "info" : config.text("logLevel");
    settingValues.i2pLog = i2pLog;
    settingValues.i2pPrivacy = bazarish::i2p::privacyName(privacy);
    settingValues.listenHost = host;
    settingValues.listenPort = port;
    settingValues.serviceNodeUrl = serviceNodeUrl;
    settingValues.gatewayListenHost = gatewayListen.has_value() ? gatewayListen->host : "";
    settingValues.gatewayListenPort = gatewayListen.has_value() ? gatewayListen->port : 0;
    settingValues.gateways = gatewayPins;
    httpOptions.settings = std::make_shared<bazarish::server::ServerSettings>(
        fs::path(argv[2]), settingValues);
    httpOptions.stateDirectory = stateDir.string();
    httpOptions.fingerprint = identity->fingerprint();
    httpOptions.sealingKey = sealing;
    httpOptions.serverCardDer = card;
    httpOptions.identity = identity;
    httpOptions.tlsCertificate = credential.certificate.string();
    httpOptions.tlsKey = credential.key.string();
    httpOptions.opsClientPins = opsClientPins;
    httpOptions.gatewaysChanged = [link = gatewayLink.get()](
                                      const std::vector<std::string>& gateways) {
        if (link != nullptr) {
            link->setGateways(gateways);
        }
    };
    const auto restartHook = std::make_shared<std::function<void()>>();
    httpOptions.requestRestart = [restartHook]() { (*restartHook)(); };

    bazarish::server::HttpApi api(storage, httpOptions);

    bazarish::RestartSwitch restart([&api]() { api.stop(); });
    *restartHook = [&restart]() { restart.request(); };

    bazarish::log::info("listening on {}:{} (private channel for facades)", host, port);
    if (gatewayLink) {
        try {
            gatewayLink->start(gatewayListen->host, gatewayListen->port);
        } catch (const std::exception& error) {
            bazarish::log::error("failed to listen on {}:{} for gateways: {}",
                gatewayListen->host, gatewayListen->port, error.what());
            return 1;
        }
        bazarish::log::info("gateways reach this server on {}:{}", gatewayListen->host,
            gatewayListen->port);
    }

    if (api.bindOps(opsListen.host, opsListen.port) <= 0) {
        bazarish::log::error(
            "failed to listen on {}:{}", opsListen.host, opsListen.port);
        return 1;
    }
    if (api.bind(host, port) <= 0) {
        if (restart.requested()) {
            return bazarish::kRestartExitCode;
        }
        bazarish::log::error("failed to listen on {}:{}", host, port);
        return 1;
    }
    api.wait();
    return restart.requested() ? bazarish::kRestartExitCode : 0;
}
