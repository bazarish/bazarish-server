// Bazarish project (c) 2026
#include "AccountApi.hpp"
#include "GrantStore.hpp"
#include "NodeSettings.hpp"
#include "OperatorPush.hpp"
#include "PortalApi.hpp"
#include "SubscriptionStore.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/ConfigFile.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/PrivateFile.hpp>
#include <bazarish/Restart.hpp>
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
#include <set>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

namespace fs = std::filesystem;

constexpr const char* kVersion = "0.0.1";
constexpr const char* kDefaultHost = "127.0.0.1";
constexpr int kDefaultPort = 8421;
// The portal's HMAC secrets are minted per run, so there is nothing to configure
// and nothing to leak: a restart simply invalidates outstanding challenges.
constexpr std::size_t kPortalSecretBytes = 16;
// How often idle accounts are looked for. The window is measured in days, so this
// only has to be far finer than that.
constexpr std::chrono::hours kIdleSweepInterval{1};
// How long the messaging server is given to start answering before the node gives
// up waiting for it. The two are restarted together and the node has work for it
// in the first second.
constexpr std::chrono::seconds kBackendWaitBudget{60};

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

// Loads the service node's own signing identity from the state directory,
// generating it on first start. The node signs its operator pushes (quota,
// transient) with it, and a backend authorises it by fingerprint.
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

// Portal onboarding presentation, parsed from the config. The message and links
// are advertised by the discovery endpoint so a client knows where to register.
struct PortalConfig {
    std::string message;
    // What the portal calls itself and where a user reaches it, in the words the
    // client shows before a login is signed. The address is what the user has in
    // the address bar, so it is the link they were given unless the operator
    // fronts the portal under another one.
    std::string name;
    std::string address;
    // What signing in here is called, in the client's badge: whose account the
    // signature opens.
    std::string role;
    std::vector<std::string> links;
    // This server's facade URLs - I2P addresses, where clients talk to it - shown
    // in the cabinet as part of the server descriptor a client pastes to connect
    // (client failover order).
    std::vector<std::string> facades;
    // Clearnet addresses a client with no router yet asks for a slice of netdb.
    // They carry nothing else.
    std::vector<std::string> reseeds;
};

// Who may be served on this node. Open registration serves an account the moment
// it is created; approval registration creates it frozen and waits for the
// operator. `message` is what a frozen user is shown - how to reach the operator
// to finish registration - and `idleDeleteDays` is how long an account is kept
// with no destination delegated here before it is deleted. That covers a client
// that stopped running, a registration nobody redeemed and an account no operator
// approved: the delegation is the only sign of life a server has.
struct RegistrationConfig {
    bool requireApproval = false;
    std::string message;
    std::int64_t idleDeleteDays = 180;
};

// Where the node runs and what it runs on. Everything a command line used to
// carry lives here, so there is one place to look and one place to change.
struct NodeConfig {
    std::string stateDir;
    std::string serverCard;
    bazarish::ConfigView::Endpoint listen{kDefaultHost, kDefaultPort};
    bazarish::ConfigView::Endpoint portalListen;
    std::string portalAssets;
    bazarish::ConfigView::Endpoint messaging;
    std::vector<std::string> operators;
    bazarish::log::Level logLevel = bazarish::log::Level::eInfo;
    // The level as the operator spelled it, so the panel can show and change the
    // same word rather than a number nobody wrote.
    std::string logLevelText = "info";
    std::uint64_t freeStorageBytes = 50 * 1024 * 1024;
    PortalConfig portal;
    RegistrationConfig registration;
    // Lets the two address lists hold each other's kind - a clearnet facade, an
    // I2P reseed. Nonsense in a deployment, and exactly what a stand on a LAN
    // needs. The client has a switch by the same name.
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
    config.portal.message = view.text("portal.message");
    config.portal.name = view.text("portal.name");
    config.portal.address = view.text("portal.address");
    config.portal.role = view.text("portal.role");
    config.portal.links = view.list("portal.links");
    config.portal.facades = view.list("portal.facades");
    config.portal.reseeds = view.list("portal.reseeds");
    config.allowFacadeWithoutI2pForDevPurposes
        = view.flag("allowFacadeWithoutI2pForDevPurposes", false);
    config.registration.requireApproval
        = view.flag("registration.requireApproval", config.registration.requireApproval);
    config.registration.message = view.text("registration.message");
    config.registration.idleDeleteDays
        = view.number("registration.idleDeleteDays", config.registration.idleDeleteDays);
    return config;
}

// The words this portal signs under until an operator changes them. The address
// has no default worth inventing: it is the one thing the user checks against
// their address bar, so an unset one stops the portal instead.
bazarish::service::LoginConsumer portalConsumer(const NodeConfig& config)
{
    const char* const kDefaultPortalName = "Bazarish service node";
    const char* const kDefaultPortalRole = "Account owner";
    bazarish::service::LoginConsumer consumer;
    consumer.name = config.portal.name.empty() ? kDefaultPortalName : config.portal.name;
    consumer.place = config.portal.address.empty()
        ? (config.portal.links.empty() ? std::string() : config.portal.links.front())
        : config.portal.address;
    consumer.role = config.portal.role.empty() ? kDefaultPortalRole : config.portal.role;
    return consumer;
}

// When this account was last heard from: the delegation it keeps here, or - for
// one that never delegated - when it registered or asked to.
std::int64_t idleSince(const std::optional<bazarish::service::SubscriptionStore::Account>& account,
    bazarish::service::GrantStore& grants, const std::string& user)
{
    if (account.has_value() && account->delegatedAt != 0) {
        return account->delegatedAt;
    }
    if (account.has_value() && account->registeredAt != 0) {
        return account->registeredAt;
    }
    if (const std::optional<bazarish::service::GrantStore::Approval> approval
        = grants.peekApproval(user);
        approval.has_value()) {
        return approval->requestedAt;
    }
    if (const std::optional<bazarish::service::GrantStore::SubscriptionGrant> grant
        = grants.peekSubscription(user);
        grant.has_value()) {
        return grant->grantedAt;
    }
    return 0;
}

// Drops every account that has gone `idleDays` without a destination delegated
// here. A ban outlives the account it removed, so only the account goes.
void sweepIdleAccounts(bazarish::service::SubscriptionStore& store,
    bazarish::service::GrantStore& grants, const bazarish::service::OperatorPush& push,
    const std::int64_t idleDays, const std::int64_t now)
{
    if (idleDays <= 0) {
        return;  // the operator keeps them forever
    }
    const std::int64_t idleSeconds = idleDays * bazarish::kSecondsPerDay;
    // A registration that never became an account is known to the grant store
    // alone; a served one is known to both.
    std::set<std::string> users;
    for (const std::string& user : grants.allUsers()) {
        users.insert(user);
    }
    for (const bazarish::service::SubscriptionStore::Account& account : store.allAccounts()) {
        users.insert(account.user);
    }
    for (const std::string& user : users) {
        const std::int64_t since = idleSince(store.getAccount(user), grants, user);
        if (since == 0 || since + idleSeconds > now) {
            continue;
        }
        if (!push.publish(user, std::string(), 0)) {
            bazarish::log::warn("destination of swept account {} not revoked on the messaging"
                                " server",
                bazarish::log::redact(user));
        }
        grants.erase(user);
        store.deleteAccount(user);
        bazarish::log::info("swept idle account {}", bazarish::log::redact(user));
    }
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

    // The messaging server must authorise this node's operator fingerprint, but
    // this node cannot start before that server has written its card. This mode
    // breaks the cycle: it materialises the identity and prints the fingerprint,
    // so the server can be started with it already configured.
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
    // The service node's own signing identity: it signs its operator pushes (quota,
    // transient) so the backends authorise it by fingerprint. Printed so the
    // operator can put it in each backend's "operators" list.
    const bazarish::Identity nodeIdentity = loadOrCreateIdentity(stateDir);
    std::printf("service-node operator fingerprint: %s\n", nodeIdentity.fingerprint().c_str());
    bazarish::service::SubscriptionStore store(stateDir / "store");
    bazarish::service::GrantStore grants(stateDir / "store");
    // The private channel carries what this node owns and the messaging server
    // must obey: the user's delegated transient and the quota their subscription
    // granted (else the messaging server would answer with its own default and
    // the user would see a different number than the portal promised).
    const std::string messagingUrl
        = "http://" + nodeConfig.messaging.host + ":" + std::to_string(nodeConfig.messaging.port);
    const bazarish::service::OperatorPush operatorPush(messagingUrl, nodeIdentity);
    // The same channel, for the pushes made while a device waits on the answer.
    // Those run on one of the account API's handful of io threads, so they are
    // given a single attempt: retrying inline would hold that thread for close to
    // two minutes whenever the messaging server is busy, and starve every other
    // request the node has - a device that was refused asks again by itself.
    const bazarish::service::OperatorPush promptPush(messagingUrl, nodeIdentity,
        bazarish::service::OperatorPush::kPromptAttempts);

    if (nodeConfig.allowFacadeWithoutI2pForDevPurposes) {
        bazarish::setAllowFacadeWithoutI2pForDevPurposes(true);
        bazarish::log::warn("facades and reseeds may hold each other's kind: development only");
    }

    // One live set of knobs for the account API and the portal, written back to
    // the config file the node was started with, so what an operator changes in
    // the panel is what the node reads at the next start.
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
    options.publishI2pTransient = [&promptPush](const std::string& user,
                                      const std::string& transientB64,
                                      const std::int64_t expiresUnix) {
        return promptPush.publish(user, transientB64, expiresUnix);
    };
    options.forgetMailbox
        = [&promptPush](const std::string& user) { return promptPush.forgetMailbox(user); };
    options.prepareServingKey = [&promptPush](const std::string& user) {
        return promptPush.prepareServingKey(user);
    };
    options.commitServingKey = [&promptPush](const std::string& user) {
        return promptPush.commitServingKey(user);
    };
    options.publishQuota = [&promptPush](const std::string& user,
                               const std::uint64_t quotaBytes) {
        if (!promptPush.publishQuota(user, quotaBytes)) {
            // Not fatal to the subscription - but the user would then be served the
            // messaging server's own default and see a figure nobody promised them.
            bazarish::log::warn("quota not pushed for {}: the messaging server refused it",
                bazarish::log::redact(user));
        }
    };
    // Filled in once the API exists; the handler reads the slot when called.
    const auto restartHook = std::make_shared<std::function<void()>>();
    options.requestRestart = [restartHook]() {
        if (*restartHook) {
            (*restartHook)();
        }
    };

    // The two daemons are restarted together, so the messaging server may still be
    // binding its port. Waited for once, here, rather than discovered by the first
    // push spending its retries on a socket that is not listening yet.
    if (!operatorPush.waitReachable(kBackendWaitBudget)) {
        bazarish::log::warn("the messaging server did not answer within {}s; what this node owes"
                            " it is refused until it does",
            kBackendWaitBudget.count());
    }
    // Quotas the messaging server may have missed: an account registered before
    // this node started pushing them would be served the messaging server's own
    // default, and the user would see a figure nobody promised. Pushing them at
    // start costs one request each.
    for (const bazarish::service::SubscriptionStore::Account& account : store.allAccounts()) {
        if (!operatorPush.publishQuota(account.user, account.quotaBytes)) {
            bazarish::log::warn("quota for {} not reconciled at start",
                bazarish::log::redact(account.user));
        }
    }

    bazarish::service::AccountApi api(store, grants, options);

    // The browser-facing portal (sign-in-with-key, which is the registration),
    // sharing the grant store with the account API.
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
        // Where the archive comes from. The portal publishes it because the portal
        // is what the clearnet reaches; the messaging server packs it because that
        // is where the netDb is.
        portalOptions.reseedArchiveUrl = messagingUrl + "/internal/i2pseeds.su3";
        portalOptions.challengeSecret = bazarish::toHex(bazarish::randomBytes(kPortalSecretBytes));
        portalOptions.sessionSecret = bazarish::toHex(bazarish::randomBytes(kPortalSecretBytes));
        portalOptions.assetsDirectory = fs::path(nodeConfig.portalAssets);
        portalOptions.settings = settings;
        // The mailbox and the devices belong to the messaging server; the portal
        // asks it, signed as this node.
        portalOptions.accountUsage = [&operatorPush](const std::string& user) {
            return operatorPush.accountUsage(user);
        };
        // A user ending their own account: the same teardown unsubscribing does.
        portalOptions.deleteAccount = [&store, &grants, &operatorPush](const std::string& user) {
            store.deleteAccount(user);
            operatorPush.publish(user, std::string(), 0);
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

    // An account lives while its owner keeps a destination delegated here.
    bazarish::StopGate stopping;
    std::thread sweeper([&]() {
        while (!stopping.waitFor(kIdleSweepInterval)) {
            try {
                sweepIdleAccounts(store, grants, operatorPush, settings->get().idleDeleteDays,
                    bazarish::nowSeconds());
            } catch (const std::exception& error) {
                // Housekeeping must not take the node down, but a sweep that never
                // runs keeps dead accounts forever, so it is reported.
                bazarish::log::warn("idle sweep failed: {}", error.what());
            }
        }
    });
    // Everything this process started is ended here, so nothing is left running
    // over state the way out destroys.
    const auto stopEverything = [&]() {
        stopping.stop();
        if (portal) {
            portal->stop();
        }
        api.stop();
    };

    // Stopping happens on the switch's own thread: a handler must not stop the
    // server it is still answering on.
    bazarish::RestartSwitch restart(stopEverything);
    *restartHook = [&restart]() { restart.request(); };

    std::printf("bazarish-service-node %s\n", kVersion);
    std::printf("bound to server: %s\n", card.server.c_str());
    std::fflush(stdout);
    bazarish::log::info("listening on {}:{} (private channel for facades)",
        nodeConfig.listen.host, nodeConfig.listen.port);

    const bool bound = api.bind(nodeConfig.listen.host, nodeConfig.listen.port) > 0;
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
