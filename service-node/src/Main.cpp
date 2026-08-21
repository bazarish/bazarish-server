// Bazarish project (c) 2026
#include "AccountApi.hpp"
#include "GrantStore.hpp"
#include "PortalApi.hpp"
#include "NodeSettings.hpp"
#include "OperatorPush.hpp"
#include <bazarish/SelfHostedCaptcha.hpp>
#include "SubscriptionStore.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/ConfigFile.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/ServerDescriptor.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
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

std::string readFileText(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open " + path.string());
    }
    return std::string(
        std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void writePrivateFile(const fs::path& path, const std::string& text)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("failed to open " + path.string());
    }
    out << text;
    if (!out) {
        throw std::runtime_error("failed to write " + path.string());
    }
    fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write);
}

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

// Portal onboarding presentation, parsed from the config. The message and
// links are advertised by the discovery endpoint so a client knows where to
// register; the captcha block governs free registration.
struct PortalConfig {
    std::string message;
    std::vector<std::string> links;
    // This server's facade URLs, shown in the cabinet as the server descriptor a
    // client pastes to connect (client failover order).
    std::vector<std::string> facades;
    bool captchaEnabled = true;
    int captchaLength = 5;
    std::int64_t captchaTtlSeconds = 300;
};

// Who may be served on this node. Open registration serves an account the
// moment it is created; approval registration creates it frozen and waits for
// the operator. `message` is what a frozen user is shown - how to reach the
// operator to finish registration - and `ttlDays` is how long a never-approved
// account is kept before it is deleted.
struct RegistrationConfig {
    bool requireApproval = false;
    std::string message;
    std::int64_t ttlDays = 7;
};

// The node's own config. Nothing here is for sale - the only knobs are the
// storage quota every account gets, how the portal presents itself, and who may
// register.
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
    std::uint64_t freeStorageBytes = 50 * 1024 * 1024;
    PortalConfig portal;
    RegistrationConfig registration;
};

NodeConfig loadNodeConfig(const fs::path& path)
{
    const nlohmann::json doc = bazarish::ConfigFile(path).read();
    const bazarish::ConfigView view(doc);

    NodeConfig config;
    config.stateDir = view.text("state");
    config.serverCard = view.text("serverCard");
    if (const std::optional<bazarish::ConfigView::Endpoint> listen = view.endpoint("listen");
        listen.has_value()) {
        config.listen = *listen;
    }
    if (const std::optional<bazarish::ConfigView::Endpoint> portal
        = view.endpoint("portal.listen");
        portal.has_value()) {
        config.portalListen = *portal;
    }
    config.portalAssets = view.text("portal.assets");
    if (const std::optional<bazarish::ConfigView::Endpoint> messaging
        = view.endpoint("messaging");
        messaging.has_value()) {
        config.messaging = *messaging;
    }
    config.operators = view.list("operators");
    if (const std::string level = view.text("logLevel"); !level.empty()) {
        const std::optional<bazarish::log::Level> parsed = bazarish::log::levelFromString(level);
        if (!parsed.has_value()) {
            throw std::runtime_error("config: logLevel is not a level");
        }
        config.logLevel = *parsed;
    }
    config.freeStorageBytes = doc.value("freeStorageBytes", config.freeStorageBytes);
    if (doc.contains("portal")) {
        const nlohmann::json& portal = doc.at("portal");
        config.portal.message = portal.value("message", std::string());
        if (portal.contains("links")) {
            config.portal.links = portal.at("links").get<std::vector<std::string>>();
        }
        if (portal.contains("facades")) {
            config.portal.facades = portal.at("facades").get<std::vector<std::string>>();
        }
        if (portal.contains("captcha")) {
            const nlohmann::json& captcha = portal.at("captcha");
            config.portal.captchaEnabled = captcha.value("enabled", true);
            config.portal.captchaLength = captcha.value("length", 5);
            config.portal.captchaTtlSeconds = captcha.value("ttlSeconds", std::int64_t{300});
        }
    }
    if (doc.contains("registration")) {
        const nlohmann::json& registration = doc.at("registration");
        config.registration.requireApproval
            = registration.value("requireApproval", config.registration.requireApproval);
        config.registration.message = registration.value("message", std::string());
        config.registration.ttlDays
            = registration.value("ttlDays", config.registration.ttlDays);
    }
    return config;
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

    const fs::path cardPath(nodeConfig.serverCard);
    const std::string host = nodeConfig.listen.host;
    const int port = nodeConfig.listen.port;
    const std::string portalHost = nodeConfig.portalListen.host;
    const int portalPort = nodeConfig.portalListen.port;
    const fs::path portalAssets(nodeConfig.portalAssets);
    const std::string messagingHost = nodeConfig.messaging.host;
    const int messagingPort = nodeConfig.messaging.port;
    const std::vector<std::string> operatorFingerprints = nodeConfig.operators;
    const bazarish::log::Level logLevel = nodeConfig.logLevel;

    bazarish::log::setComponent("service-node");
    bazarish::log::setLevel(logLevel);

    const bazarish::Bytes cardDer = readFileBytes(cardPath);
    const bazarish::ServerCard card = bazarish::ServerCard::verify(cardDer);

    fs::create_directories(stateDir);
    // The service node's own signing identity: it signs its operator pushes
    // (quota, transient) so the backends authorise it by fingerprint. Print the
    // fingerprint so the operator can list it in each backend's
    // --operator-fingerprint.
    const bazarish::Identity nodeIdentity = loadOrCreateIdentity(stateDir);
    std::printf("service-node operator fingerprint: %s\n", nodeIdentity.fingerprint().c_str());
    bazarish::service::SubscriptionStore store(stateDir / "store");
    bazarish::service::GrantStore grants(stateDir / "store");
    // The private channel carries what this node owns and the messaging server
    // must obey: the user's delegated transient and the quota their subscription
    // granted (else the messaging server would answer with its own default and
    // the user would see a different number than the portal promised).
    const std::string messagingUrl = messagingPort > 0
        ? "http://" + messagingHost + ":" + std::to_string(messagingPort)
        : std::string();
    const bazarish::service::OperatorPush operatorPush(messagingUrl, nodeIdentity);

    bazarish::service::AccountApiOptions options;
    options.serverFingerprint = card.server;
    options.serverCardDer = cardDer;
    options.version = kVersion;
    options.operatorFingerprints = operatorFingerprints;
    // One live set of knobs for the account API and the portal, written back to
    // the config file the node was started with, so what an operator changes in
    // the panel is what the node reads at the next start.
    const auto settings = std::make_shared<bazarish::service::NodeSettings>(configPath,
        bazarish::service::NodeSettings::Values{nodeConfig.registration.requireApproval,
            nodeConfig.registration.message, nodeConfig.freeStorageBytes,
            nodeConfig.registration.ttlDays});
    options.settings = settings;
    options.defaultQuotaBytes = nodeConfig.freeStorageBytes;
    options.portalMessage = nodeConfig.portal.message;
    options.portalLinks = nodeConfig.portal.links;
    options.freeRegistrationCaptcha = nodeConfig.portal.captchaEnabled;
    options.registration = nodeConfig.registration.requireApproval
        ? bazarish::service::AccountApiOptions::Registration::eApproval
        : bazarish::service::AccountApiOptions::Registration::eOpen;
    options.registrationMessage = nodeConfig.registration.message;
    options.publishI2pTransient = [&operatorPush](const std::string& user,
                                      const std::string& transientB64,
                                      const std::int64_t expiresUnix) {
        return operatorPush.publish(user, transientB64, expiresUnix);
    };
    options.publishQuota = [&operatorPush](const std::string& user,
                               const std::uint64_t quotaBytes) {
        if (!operatorPush.publishQuota(user, quotaBytes)) {
            // Not fatal to the subscription - but the user would then be served the
            // messaging server's own default and see a figure nobody promised them.
            bazarish::log::warn("quota not pushed for {}: the messaging server refused it",
                bazarish::log::redact(user));
        }
    };
    // Quotas the messaging server may have missed: an account that subscribed
    // before this node started pushing them would be served the messaging
    // server's own default until its next renewal, and the user would see a
    // figure nobody promised. Pushing them at start costs one request each.
    for (const bazarish::service::SubscriptionStore::Subscription& subscription :
        store.allSubscriptions()) {
        if (!operatorPush.publishQuota(subscription.user, subscription.quotaBytes)) {
            bazarish::log::warn("quota for {} not reconciled at start",
                bazarish::log::redact(subscription.user));
        }
    }

    bazarish::service::AccountApi api(store, grants, options);

    // The browser-facing portal (sign-in-with-key, captcha registration, ...),
    // sharing the grant store with the account API. Secrets are per-run; a
    // restart simply invalidates outstanding challenges/sessions.
    static std::unique_ptr<bazarish::service::SelfHostedCaptcha> captcha;
    static std::unique_ptr<bazarish::service::PortalApi> portal;
    static std::thread portalThread;
    if (portalPort > 0) {
        if (portalAssets.empty()) {
            bazarish::log::error("--portal-listen needs --portal-assets: the portal serves its "
                                 "pages from files, not from the binary");
            return 2;
        }
        captcha = std::make_unique<bazarish::service::SelfHostedCaptcha>(
            bazarish::toHex(bazarish::randomBytes(16)), nodeConfig.portal.captchaLength,
            nodeConfig.portal.captchaTtlSeconds);
        bazarish::service::PortalApiOptions portalOptions;
        portalOptions.audience = card.server;
        // The server descriptor a client pastes to connect: this server's
        // fingerprint plus its configured facade URLs, shown in the cabinet.
        portalOptions.serverDescriptor = bazarish::encodeServerDescriptor(
            {card.server, nodeConfig.portal.facades});
        portalOptions.requireCaptcha = nodeConfig.portal.captchaEnabled;
        portalOptions.challengeSecret = bazarish::toHex(bazarish::randomBytes(16));
        portalOptions.sessionSecret = bazarish::toHex(bazarish::randomBytes(16));
        portalOptions.defaultQuotaBytes = options.defaultQuotaBytes;
        portalOptions.freeSubscriptionTermSeconds = options.maxTermSeconds;
        portalOptions.requiresApproval = nodeConfig.registration.requireApproval;
        portalOptions.registrationMessage = nodeConfig.registration.message;
        portalOptions.assetsDirectory = portalAssets;
        portalOptions.settings = settings;
        // The mailbox and the devices belong to the messaging server; the portal
        // asks it, signed as this node.
        portalOptions.accountUsage = [&operatorPush](const std::string& user)
            -> std::optional<bazarish::service::PortalApiOptions::Usage> {
            const std::optional<bazarish::service::OperatorPush::AccountUsage> usage
                = operatorPush.accountUsage(user);
            if (!usage.has_value()) {
                return std::nullopt;
            }
            return bazarish::service::PortalApiOptions::Usage{
                usage->usedBytes, usage->quotaBytes, usage->devices};
        };
        // A user ending their own account: the same teardown unsubscribing does.
        portalOptions.deleteAccount = [&store, &grants, &operatorPush](const std::string& user) {
            store.deleteSubscription(user);
            operatorPush.publish(user, std::string(), 0);
            grants.erase(user);
            bazarish::log::info("account deleted by its owner: {}", bazarish::log::redact(user));
        };
        try {
            portal = std::make_unique<bazarish::service::PortalApi>(portalOptions, *captcha, grants);
        } catch (const std::exception& error) {
            bazarish::log::error("portal not started: {}", error.what());
            return 2;
        }
        portalThread = std::thread(
            [portalHost, portalPort]() { portal->listen(portalHost, portalPort); });
        portalThread.detach();
        bazarish::log::info("portal on {}:{}", portalHost, portalPort);
    }

    // A moderated node accumulates accounts nobody ever approves. Sweep them so a
    // dead registration does not sit there forever holding a fingerprint.
    static std::thread sweepThread;
    sweepThread = std::thread([&grants, &store, settings]() {
        constexpr std::int64_t kSecondsPerDay = 24 * 3600;
        while (true) {
            std::this_thread::sleep_for(std::chrono::hours(1));
            const std::int64_t ttlDays = settings->get().registrationTtlDays;
            if (ttlDays <= 0) {
                continue;  // the operator keeps them forever
            }
            const std::int64_t ttlSeconds = ttlDays * kSecondsPerDay;
            const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
            for (const std::string& user : grants.allUsers()) {
                const std::optional<bazarish::service::GrantStore::Approval> approval
                    = grants.peekApproval(user);
                const std::optional<bazarish::service::GrantStore::SubscriptionGrant> grant
                    = grants.peekSubscription(user);
                // An account waiting for an operator who never came, and a portal
                // registration no client ever redeemed: neither is a served
                // account, and neither should hold a fingerprint forever.
                std::int64_t since = 0;
                if (approval.has_value() && approval->pending()) {
                    since = approval->requestedAt;
                } else if (!approval.has_value() && grant.has_value()) {
                    since = grant->grantedAt;
                }
                if (since == 0 || since + ttlSeconds > now) {
                    continue;
                }
                grants.erase(user);
                store.deleteSubscription(user);
                bazarish::log::info("swept unfinished registration {}", user.substr(0, 12));
            }
        }
    });
    sweepThread.detach();

    std::printf("bazarish-service-node %s\n", kVersion);
    std::printf("bound to server: %s\n", card.server.c_str());
    std::fflush(stdout);
    bazarish::log::info("listening on {}:{} (private channel for facades)", host, port);

    if (!api.listen(host, port)) {
        bazarish::log::error("failed to listen on {}:{}", host, port);
        return 1;
    }
    return 0;
}
