// Bazarish project (c) 2026
#include "AccountApi.hpp"
#include "GrantStore.hpp"
#include "IdleSweep.hpp"
#include "NodeSettings.hpp"
#include "OperatorPush.hpp"
#include "PortalApi.hpp"
#include "SubscriptionStore.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/ConfigFile.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/PrivateFile.hpp>
#include <bazarish/Tls.hpp>
#include <Restart.hpp>
#include <bazarish/ServerDescriptor.hpp>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

namespace fs = std::filesystem;

constexpr const char* kVersion = "0.0.1";
constexpr const char* kDefaultHost = "127.0.0.1";
constexpr int kDefaultPort = 8421;
constexpr int kDefaultOpsPort = 8427;
constexpr std::size_t kPortalSecretBytes = 16;
constexpr std::chrono::hours kIdleSweepInterval{1};
constexpr std::chrono::seconds kBackendWaitBudget{60};
constexpr const char* kDefaultPortalMessage
    = "Registration here is confirmed by hand. The portal is at example.i2p";
constexpr const char* kDefaultRegistrationMessage
    = "Send a few sentences about yourself and your key fingerprint to me@example.com.";

void printUsage()
{
    std::printf(
        "bazarish-service-node %s\n"
        "Usage: bazarish-service-node --config <path>\n"
        "       bazarish-service-node --config <path> --fingerprint\n"
        "       bazarish-service-node --version\n"
        "\n"
        "Everything this node runs on is in the config file: where its state\n"
        "lives, the server card that binds it to its messaging server, the\n"
        "addresses it listens on and reaches, who may act as operator, and what\n"
        "new accounts get. Nothing is settable twice - a flag that could override\n"
        "the file would mean two answers to the same question.\n"
        "--fingerprint prints this node's operator fingerprint (creating its\n"
        "identity if needed) and exits, so the messaging server can be started\n"
        "with it already authorised before this node runs.\n",
        kVersion);
}

bazarish::Bytes readFileBytes(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open " + path.string());
    }
    return bazarish::Bytes(
        std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

using bazarish::readFileText;
using bazarish::writePrivateFile;

bazarish::Identity loadOrCreateIdentity(const fs::path& stateDir)
{
    const fs::path path = stateDir / "identity.pem";
    if (fs::exists(path)) {
        return bazarish::Identity::fromPrivatePem(readFileText(path));
    }
    bazarish::Identity identity = bazarish::Identity::generate();
    writePrivateFile(path, identity.privatePem());
    return identity;
}

struct PortalConfig {
    std::string message = kDefaultPortalMessage;
    std::string name;
    std::vector<std::string> address;
    std::string role;
    std::vector<std::string> links;
    std::vector<std::string> facades;
    std::vector<std::string> reseeds;
};

struct RegistrationConfig {
    bool requireApproval = false;
    std::string message = kDefaultRegistrationMessage;
    std::int64_t idleDeleteDays = 180;
};

struct NodeConfig {
    std::string stateDir;
    std::string serverCard;
    bazarish::ConfigView::Endpoint listen{kDefaultHost, kDefaultPort};
    bazarish::ConfigView::Endpoint portalListen;
    std::string portalAssets;
    bazarish::ConfigView::Endpoint messaging;
    std::string messagingPin;
    bazarish::ConfigView::Endpoint opsListen{kDefaultHost, kDefaultOpsPort};
    std::vector<std::string> opsClients;
    std::vector<std::string> operators;
    bazarish::log::Level logLevel = bazarish::log::Level::eInfo;
    std::string logLevelText = "info";
    std::uint64_t freeStorageBytes = 50 * 1024 * 1024;
    PortalConfig portal;
    RegistrationConfig registration;
    bool allowFacadeWithoutI2pForDevPurposes = false;
};

NodeConfig loadNodeConfig(const fs::path& path)
{
    const bazarish::ConfigView view(bazarish::ConfigFile(path).read());

    NodeConfig config;
    config.stateDir = view.text("state");
    config.serverCard = view.text("serverCard");
    config.listen = view.endpoint("listen").value_or(config.listen);
    config.portalListen = view.endpoint("portal.listen").value_or(config.portalListen);
    config.portalAssets = view.text("portal.assets");
    config.messaging = view.endpoint("messaging").value_or(config.messaging);
    config.messagingPin = view.text("messaging.pin");
    config.opsListen = view.endpoint("opsListen").value_or(config.opsListen);
    config.opsClients = view.list("opsClients");
    config.operators = view.list("operators");
    if (const std::string level = view.text("logLevel"); !level.empty()) {
        const std::optional<bazarish::log::Level> parsed = bazarish::log::levelFromString(level);
        if (!parsed.has_value()) {
            throw std::runtime_error("config: logLevel is not a level");
        }
        config.logLevel = *parsed;
        config.logLevelText = level;
    }
    config.freeStorageBytes = static_cast<std::uint64_t>(
        view.number("freeStorageBytes", static_cast<std::int64_t>(config.freeStorageBytes)));
    config.portal.message = view.text("portal.message", config.portal.message);
    config.portal.name = view.text("portal.name");
    config.portal.address = view.list("portal.address");
    config.portal.role = view.text("portal.role");
    config.portal.links = view.list("portal.links");
    config.portal.facades = view.list("portal.facades");
    config.portal.reseeds = view.list("portal.reseeds");
    for (const std::string& reseed : config.portal.reseeds) {
        if (!bazarish::i2p::isReseedUrl(reseed)) {
            throw std::invalid_argument("portal.reseeds holds " + reseed + ", not an https URL");
        }
    }
    config.allowFacadeWithoutI2pForDevPurposes
        = view.flag("allowFacadeWithoutI2pForDevPurposes", false);
    config.registration.requireApproval
        = view.flag("registration.requireApproval", config.registration.requireApproval);
    config.registration.message
        = view.text("registration.message", config.registration.message);
    config.registration.idleDeleteDays
        = view.number("registration.idleDeleteDays", config.registration.idleDeleteDays);
    return config;
}

bazarish::service::LoginConsumer portalConsumer(const NodeConfig& config)
{
    const char* const kDefaultPortalName = "Bazarish server";
    const char* const kDefaultPortalRole = "Account owner";
    bazarish::service::LoginConsumer consumer;
    consumer.name = config.portal.name.empty() ? kDefaultPortalName : config.portal.name;
    consumer.place = config.portal.address.empty() ? config.portal.links
                                                   : config.portal.address;
    consumer.role = config.portal.role.empty() ? kDefaultPortalRole : config.portal.role;
    return consumer;
}

}  // namespace

int main(const int argc, const char** argv)
{
    if (argc == 2 && std::strcmp(argv[1], "--version") == 0) {
        std::printf("bazarish-service-node %s\n", kVersion);
        return 0;
    }
    if (argc < 3 || std::strcmp(argv[1], "--config") != 0) {
        printUsage();
        return 2;
    }
    const fs::path configPath(argv[2]);
    NodeConfig nodeConfig;
    try {
        nodeConfig = loadNodeConfig(configPath);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "config: %s\n", error.what());
        return 2;
    }
    if (nodeConfig.stateDir.empty() || nodeConfig.serverCard.empty()) {
        std::fprintf(stderr, "config: \"state\" and \"serverCard\" are required\n");
        return 2;
    }
    const fs::path stateDir(nodeConfig.stateDir);

    if (argc == 4 && std::strcmp(argv[3], "--fingerprint") == 0) {
        fs::create_directories(stateDir);
        std::printf("%s\n", loadOrCreateIdentity(stateDir).fingerprint().c_str());
        return 0;
    }
    if (argc != 3) {
        printUsage();
        return 2;
    }

    if (nodeConfig.messaging.port <= 0) {
        std::fprintf(stderr, "config: \"messaging\" is required - a node whose messaging server"
                             " it cannot reach\ncan register an account and then serve nobody\n");
        return 2;
    }

    bazarish::log::setComponent("service-node");
    bazarish::log::setLevel(nodeConfig.logLevel);

    const bazarish::Bytes cardDer = readFileBytes(fs::path(nodeConfig.serverCard));
    const bazarish::ServerCard card = bazarish::ServerCard::verify(cardDer);

    fs::create_directories(stateDir);
    const bazarish::Identity nodeIdentity = loadOrCreateIdentity(stateDir);
    const bazarish::tls::Credential credential = bazarish::tls::selfSigned(stateDir);
    std::printf("service-node operator fingerprint: %s\n", nodeIdentity.fingerprint().c_str());
    std::printf("service-node socket pin: %s\n", credential.pin.c_str());
    bazarish::service::SubscriptionStore store(stateDir / "store");
    bazarish::service::GrantStore grants(stateDir / "store");
    const std::string messagingUrl = "https://" + nodeConfig.messaging.host + ":"
        + std::to_string(nodeConfig.messaging.port);
    const bazarish::service::OperatorPush::Dial backend{messagingUrl, nodeConfig.messagingPin,
        credential.certificate.string(), credential.key.string()};
    const bazarish::service::OperatorPush operatorPush(backend, nodeIdentity);
    const bazarish::service::OperatorPush promptPush(backend, nodeIdentity,
        bazarish::service::OperatorPush::kPromptAttempts);

    if (nodeConfig.allowFacadeWithoutI2pForDevPurposes) {
        bazarish::setAllowFacadeWithoutI2pForDevPurposes(true);
        bazarish::log::warn("facades and reseeds may hold each other's kind: development only");
    }

    const auto settings = std::make_shared<bazarish::service::NodeSettings>(configPath,
        bazarish::service::NodeSettings::Values{
            .requireApproval = nodeConfig.registration.requireApproval,
            .registrationMessage = nodeConfig.registration.message,
            .portalMessage = nodeConfig.portal.message,
            .loginConsumer = portalConsumer(nodeConfig),
            .facades = nodeConfig.portal.facades,
            .reseeds = nodeConfig.portal.reseeds,
            .portalLinks = nodeConfig.portal.links,
            .logLevel = nodeConfig.logLevelText,
            .listenHost = nodeConfig.listen.host,
            .listenPort = nodeConfig.listen.port,
            .portalListenHost = nodeConfig.portalListen.host,
            .portalListenPort = nodeConfig.portalListen.port,
            .messagingHost = nodeConfig.messaging.host,
            .messagingPort = nodeConfig.messaging.port,
            .defaultQuotaBytes = nodeConfig.freeStorageBytes,
            .idleDeleteDays = nodeConfig.registration.idleDeleteDays});

    bazarish::service::AccountApiOptions options;
    options.serverFingerprint = card.server;
    options.serverCardDer = cardDer;
    options.version = kVersion;
    options.operatorFingerprints = nodeConfig.operators;
    options.settings = settings;
    options.tlsCertificate = credential.certificate.string();
    options.tlsKey = credential.key.string();
    options.opsClientPins = nodeConfig.opsClients;
    options.publishI2pTransient = [&promptPush](const std::string& user,
                                      const std::string& transientB64,
                                      const std::int64_t expiresUnix,
                                      const bazarish::service::AddressKeys& keys) {
        return promptPush.publish(user, transientB64, expiresUnix, keys);
    };
    options.forgetMailbox
        = [&promptPush](const std::string& user) { return promptPush.forgetMailbox(user); };
    options.publishQuota = [&promptPush](const std::string& user,
                               const std::uint64_t quotaBytes) {
        if (!promptPush.publishQuota(user, quotaBytes)) {
            bazarish::log::warn("quota not pushed for {}: the messaging server refused it",
                bazarish::log::redact(user));
        }
    };
    const auto restartHook = std::make_shared<std::function<void()>>();
    options.requestRestart = [restartHook]() {
        if (*restartHook) {
            (*restartHook)();
        }
    };

    if (!operatorPush.waitReachable(kBackendWaitBudget)) {
        bazarish::log::warn("the messaging server did not answer within {}s; what this node owes"
                            " it is refused until it does",
            kBackendWaitBudget.count());
    }
    for (const bazarish::service::SubscriptionStore::Account& account : store.allAccounts()) {
        if (!operatorPush.publishQuota(account.user, account.quotaBytes)) {
            bazarish::log::warn("quota for {} not reconciled at start",
                bazarish::log::redact(account.user));
        }
    }

    bazarish::service::AccountApi api(store, grants, options);

    std::unique_ptr<bazarish::service::PortalApi> portal;
    if (nodeConfig.portalListen.port > 0) {
        if (nodeConfig.portalAssets.empty()) {
            bazarish::log::error("config: \"portal.listen\" needs \"portal.assets\": the portal"
                                 " serves its pages from files, not from the binary");
            return 2;
        }
        if (settings->get().loginConsumer.place.empty()) {
            bazarish::log::error("config: \"portal.listen\" needs \"portal.address\" (or"
                                 " \"portal.links\"): a portal that will not say where it lives"
                                 " asks users to sign for a name they cannot check");
            return 2;
        }
        bazarish::service::PortalApiOptions portalOptions;
        portalOptions.serverFingerprint = card.server;
        portalOptions.fetchReseedArchive
            = [&operatorPush]() { return operatorPush.reseedArchive(); };
        portalOptions.challengeSecret = bazarish::toHex(bazarish::randomBytes(kPortalSecretBytes));
        portalOptions.sessionSecret = bazarish::toHex(bazarish::randomBytes(kPortalSecretBytes));
        portalOptions.assetsDirectory = fs::path(nodeConfig.portalAssets);
        portalOptions.settings = settings;
        portalOptions.accountUsage = [&operatorPush](const std::string& user) {
            return operatorPush.accountUsage(user);
        };
        portalOptions.deleteAccount = [&store, &grants, &operatorPush](const std::string& user) {
            store.deleteAccount(user);
            if (!operatorPush.publish(user, std::string(), 0, {})) {
                bazarish::log::warn("destination of {} was not taken down: the messaging server "
                    "refused it", bazarish::log::redact(user));
            }
            if (!operatorPush.forgetMailbox(user)) {
                bazarish::log::warn("mailbox of {} was not dropped: the messaging server refused it",
                    bazarish::log::redact(user));
            }
            grants.erase(user);
            bazarish::log::info("account deleted by its owner: {}", bazarish::log::redact(user));
        };
        try {
            portal = std::make_unique<bazarish::service::PortalApi>(portalOptions, grants);
        } catch (const std::exception& error) {
            bazarish::log::error("portal not started: {}", error.what());
            return 2;
        }
        if (portal->bind(nodeConfig.portalListen.host, nodeConfig.portalListen.port) <= 0) {
            bazarish::log::error("failed to listen on {}:{} (portal)",
                nodeConfig.portalListen.host, nodeConfig.portalListen.port);
            return 1;
        }
        bazarish::log::info(
            "portal on {}:{}", nodeConfig.portalListen.host, nodeConfig.portalListen.port);
    }

    bazarish::StopGate stopping;
    std::thread sweeper([&]() {
        while (!stopping.waitFor(kIdleSweepInterval)) {
            try {
                bazarish::service::sweepIdleAccounts(store, grants, operatorPush, settings->get().idleDeleteDays,
                    bazarish::nowSeconds());
            } catch (const std::exception& error) {
                bazarish::log::warn("idle sweep failed: {}", error.what());
            }
        }
    });
    const auto stopEverything = [&]() {
        stopping.stop();
        if (portal) {
            portal->stop();
        }
        api.stop();
    };

    bazarish::RestartSwitch restart(stopEverything);
    *restartHook = [&restart]() { restart.request(); };

    std::printf("bazarish-service-node %s\n", kVersion);
    std::printf("bound to server: %s\n", card.server.c_str());
    std::fflush(stdout);
    bazarish::log::info("listening on {}:{} (private channel for facades)",
        nodeConfig.listen.host, nodeConfig.listen.port);

    const bool boundOps = api.bindOps(nodeConfig.opsListen.host, nodeConfig.opsListen.port) > 0;
    const bool bound
        = boundOps && api.bind(nodeConfig.listen.host, nodeConfig.listen.port) > 0;
    if (bound) {
        api.wait();
    } else {
        bazarish::log::error(
            "failed to listen on {}:{}", nodeConfig.listen.host, nodeConfig.listen.port);
    }
    stopEverything();
    sweeper.join();
    if (!bound) {
        return restart.requested() ? bazarish::kRestartExitCode : 1;
    }
    return restart.requested() ? bazarish::kRestartExitCode : 0;
}
