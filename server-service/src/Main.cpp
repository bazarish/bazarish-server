// Bazarish project (c) 2026
#include "AccountApi.hpp"

#include <ServicePorts.hpp>
#include <LogRing.hpp>
#include <OpsSettings.hpp>
#include <Restart.hpp>
#include <StateIdentity.hpp>

#include "AccountRemoval.hpp"
#include "GrantStore.hpp"
#include "IdleSweep.hpp"
#include "NodeSettings.hpp"
#include "OperatorPush.hpp"
#include "PortalApi.hpp"
#include "PushQueue.hpp"
#include "SubscriptionStore.hpp"
#include <CommandLine.hpp>

#include <BuildVersion.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/ConfigFile.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/PrivateFile.hpp>
#include <bazarish/Tls.hpp>

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
#include <variant>

namespace {

namespace fs = std::filesystem;

constexpr const char* kDefaultHost = bazarish::ports::kLoopback;
constexpr int kDefaultPort = bazarish::ports::kServerServicePort;
constexpr int kDefaultOpsPort = bazarish::ports::kServerServiceOpsPort;
constexpr std::size_t kPortalSecretBytes = 16;
constexpr std::chrono::hours kIdleSweepInterval{1};
constexpr const char* kDefaultRegistrationMessage
    = "Send a few sentences about yourself and your key fingerprint to me@example.com";

void printUsage()
{
    std::printf(
        "bazarish-server-service %s\n"
        "Usage: bazarish-server-service --config <path>\n"
        "       bazarish-server-service --config <path> --fingerprint\n"
        "       bazarish-server-service --version\n"
        "\n"
        "Everything this server service runs on is in the config file: where its state\n"
        "lives, the server card that binds it to its messaging server, the\n"
        "addresses it listens on and reaches, who may act as operator, and what\n"
        "new accounts get. Nothing is settable twice - a flag that could override\n"
        "the file would mean two answers to the same question.\n"
        "--fingerprint prints this server service's operator fingerprint (creating its\n"
        "identity if needed) and exits, so the messaging server can be started\n"
        "with it already authorised before this server service runs.\n",
        bazarish::kBuildVersion);
}


struct PortalConfig {
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
};

NodeConfig loadNodeConfig(const fs::path& path)
{
    const bazarish::ConfigView view(bazarish::ConfigFile(path).read());

    NodeConfig config;
    config.stateDir = view.text("state");
    config.listen = view.endpoint("listen").value_or(config.listen);
    config.portalListen = view.endpoint("portal.listen").value_or(config.portalListen);
    config.portalAssets = view.text("portal.assets");
    config.messaging = view.endpoint("messaging").value_or(config.messaging);
    config.messagingPin = view.text("messaging.pin");
    config.opsListen = view.endpoint("opsListen").value_or(config.opsListen);
    config.opsClients = view.list("opsClients");
    config.operators = view.list("operators");
    config.logLevel = bazarish::server::configLogLevel(view);
    if (const std::string level = view.text("logLevel"); !level.empty()) {
        config.logLevelText = level;
    }
    config.freeStorageBytes = static_cast<std::uint64_t>(
        view.number("freeStorageBytes", static_cast<std::int64_t>(config.freeStorageBytes)));
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
    const bool fingerprintOnly = argc == 4 && std::strcmp(argv[3], "--fingerprint") == 0;
    const std::variant<fs::path, int> argument = bazarish::server::configArgument(
        fingerprintOnly ? 3 : argc, argv,
        std::string("bazarish-server-service ") + bazarish::kBuildVersion, printUsage);
    if (const int* const status = std::get_if<int>(&argument)) {
        return *status;
    }
    const fs::path configPath = std::get<fs::path>(argument);
    NodeConfig nodeConfig;
    try {
        nodeConfig = loadNodeConfig(configPath);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "config: %s\n", error.what());
        return 2;
    }
    if (nodeConfig.stateDir.empty()) {
        std::fprintf(stderr, "config: \"state\" is required\n");
        return 2;
    }
    const fs::path stateDir(nodeConfig.stateDir);

    if (fingerprintOnly) {
        fs::create_directories(stateDir);
        std::printf("%s\n", bazarish::server::loadOrCreateIdentity(stateDir).fingerprint().c_str());
        return 0;
    }
    if (nodeConfig.messaging.port <= 0) {
        std::fprintf(stderr, "config: \"messaging\" is required - a server service whose messaging server"
                             " it cannot reach\ncan register an account and then serve nobody\n");
        return 2;
    }

    bazarish::log::setComponent("server-service");
    bazarish::log::setLevel(nodeConfig.logLevel);
    const auto logRing = std::make_shared<bazarish::server::LogRing>();
    const bazarish::server::LogCapture logCapture(logRing);

    fs::create_directories(stateDir);
    const bazarish::Identity nodeIdentity = bazarish::server::loadOrCreateIdentity(stateDir);
    const auto sealing = std::make_shared<bazarish::Key>(bazarish::server::loadOrCreateSealingKey(stateDir));
    const bazarish::tls::Credential credential = bazarish::tls::selfSigned(stateDir);
    std::printf("server-service operator fingerprint: %s\n", nodeIdentity.fingerprint().c_str());
    std::printf("server-service socket pin: %s\n", credential.pin.c_str());
    bazarish::service::SubscriptionStore store(stateDir / "store");
    bazarish::service::GrantStore grants(stateDir / "store");
    const std::string messagingUrl = "https://" + nodeConfig.messaging.host + ":"
        + std::to_string(nodeConfig.messaging.port);
    const bazarish::service::OperatorPush::Dial backend{messagingUrl, nodeConfig.messagingPin,
        credential.certificate.string(), credential.key.string()};
    const auto userLocks = std::make_shared<bazarish::service::UserLocks>();
    const bazarish::service::OperatorPush queuePush(backend, nodeIdentity);
    std::shared_ptr<bazarish::service::PushQueue> pushes;
    try {
        pushes = std::make_shared<bazarish::service::PushQueue>(stateDir / "store", store,
            *userLocks,
            bazarish::service::PushQueue::Delivery{
                .quota =
                    [&queuePush](const std::string& user, const std::uint64_t quotaBytes) {
                        return queuePush.publishQuota(user, quotaBytes);
                    },
                .card =
                    [&queuePush](const std::string& user) {
                        return queuePush.publishCardChanged(user);
                    },
                .takeDownAddress =
                    [&queuePush](const std::string& user) {
                        return queuePush.takeDownAddress(user);
                    },
                .forget =
                    [&queuePush](const std::string& user) {
                        return queuePush.forgetAccount(user);
                    }});
    } catch (const std::exception& error) {
        bazarish::log::error("the unsent marks cannot be read: {}", error.what());
        return 1;
    }
    const bazarish::service::OperatorPush operatorPush(
        backend, nodeIdentity, [pushes]() { pushes->serverReached(); });

    const auto settings = std::make_shared<bazarish::service::NodeSettings>(configPath,
        bazarish::service::NodeSettings::Values{
            .requireApproval = nodeConfig.registration.requireApproval,
            .registrationMessage = nodeConfig.registration.message,
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
    options.sealingKey = sealing;
    options.version = bazarish::kBuildVersion;
    options.operatorFingerprints = nodeConfig.operators;
    options.settings = settings;
    options.logRing = logRing;
    const auto logins = std::make_shared<bazarish::service::LoginMailbox>();
    options.logins = logins;
    options.tlsCertificate = credential.certificate.string();
    options.tlsKey = credential.key.string();
    options.opsClientPins = nodeConfig.opsClients;
    options.userLocks = userLocks;
    options.pushes = pushes;
    options.publishI2pTransient = [&operatorPush](const std::string& user,
                                      const std::string& transientB64,
                                      const std::int64_t expiresUnix,
                                      const bazarish::service::AddressKeys& keys) {
        return operatorPush.publish(user, transientB64, expiresUnix, keys);
    };
    const auto restartHook = std::make_shared<std::function<void()>>();
    options.requestRestart = [restartHook]() { (*restartHook)(); };

    const std::optional<bazarish::Bytes> nodeCard = operatorPush.nodeCard(sealing->publicDer());
    if (!nodeCard.has_value()) {
        bazarish::log::error("the messaging server issued this server service no card: no client could open"
                             " a tunnel to it");
        return 1;
    }
    // The pinned link to the messaging server vouches for the card, so its signer is the server.
    const std::string serverFingerprint
        = bazarish::ServerCard::verify(*nodeCard, bazarish::ServerCard::Service::eServerService).server;
    options.serverFingerprint = serverFingerprint;
    options.nodeCardDer = *nodeCard;

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
        portalOptions.serverFingerprint = serverFingerprint;
        portalOptions.fetchReseedArchive
            = [&operatorPush]() { return operatorPush.reseedArchive(); };
        portalOptions.challengeSecret = bazarish::toHex(bazarish::randomBytes(kPortalSecretBytes));
        portalOptions.sessionSecret = bazarish::toHex(bazarish::randomBytes(kPortalSecretBytes));
        portalOptions.assetsDirectory = fs::path(nodeConfig.portalAssets);
        portalOptions.settings = settings;
        portalOptions.logins = logins;
        portalOptions.accountUsage = [&operatorPush](const std::string& user) {
            return operatorPush.accountUsage(user);
        };
        portalOptions.deleteAccount
            = [&store, &grants, pushes, userLocks](const std::string& user) {
                  const bazarish::service::UserLocks::Held held = userLocks->hold(user);
                  bazarish::service::removeAccount(user, store, grants, *pushes);
                  bazarish::log::info(
                      "account deleted by its owner: {}", bazarish::log::redact(user));
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
                bazarish::service::sweepIdleAccounts(store, grants, *pushes,
                    settings->get().idleDeleteDays, bazarish::nowSeconds(), stopping, *userLocks);
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

    std::printf("bazarish-server-service %s\n", bazarish::kBuildVersion);
    std::printf("bound to server: %s\n", serverFingerprint.c_str());
    std::fflush(stdout);
    bazarish::log::info("listening on {}:{} (private channel for facades and the messaging server)",
        nodeConfig.listen.host, nodeConfig.listen.port);

    const bool boundOps = api.bindOps(nodeConfig.opsListen.host, nodeConfig.opsListen.port) > 0;
    const bool bound
        = boundOps && api.bind(nodeConfig.listen.host, nodeConfig.listen.port) > 0;
    if (bound) {
        api.wait();
    } else {
        bazarish::log::error(
            "failed to listen on {}:{}", nodeConfig.listen.host, nodeConfig.listen.port);
        stopEverything();
    }
    sweeper.join();
    if (!bound) {
        return restart.requested() ? bazarish::kRestartExitCode : 1;
    }
    return restart.requested() ? bazarish::kRestartExitCode : 0;
}
