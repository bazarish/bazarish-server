// Bazarish project (c) 2026
#include "AccountApi.hpp"
#include "GrantStore.hpp"
#include "PortalApi.hpp"
#include "OperatorPush.hpp"
#include <bazarish/SelfHostedCaptcha.hpp>
#include "SubscriptionStore.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Certificates.hpp>
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
        "Usage: bazarish-service-node --state <dir> --server-card <path>\n"
        "         [--listen <host> <port>] [--portal-listen <host> <port>]\n"
        "         [--config <path>]\n"
        "         [--messaging <host> <port>]\n"
        "         [--operator-fingerprint <fp>]... [--log-level <error|warn|info|debug>]\n"
        "       bazarish-service-node --state <dir> --fingerprint\n"
        "       bazarish-service-node --version\n"
        "\n"
        "The server card (produced by bazarish-server --i2p) binds this\n"
        "service node to its messaging server and is returned to clients on\n"
        "subscribe.\n"
        "--fingerprint prints this node's operator fingerprint (creating its\n"
        "identity if needed) and exits, so the messaging server can be started\n"
        "with --operator-fingerprint before this node runs.\n",
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
struct NodeConfig {
    std::uint64_t freeStorageBytes = 20 * 1024 * 1024;
    PortalConfig portal;
    RegistrationConfig registration;
};

NodeConfig loadNodeConfig(const fs::path& path)
{
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("failed to open node config " + path.string());
    }
    const nlohmann::json doc = nlohmann::json::parse(in);

    NodeConfig config;
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
    // The messaging server must authorise this node's operator fingerprint, but
    // this node cannot start before that server has written its card. This mode
    // breaks the cycle: it materialises the identity and prints the fingerprint,
    // so the server can be started with it already configured.
    if (argc == 4 && std::strcmp(argv[1], "--state") == 0
        && std::strcmp(argv[3], "--fingerprint") == 0) {
        std::printf("%s\n", loadOrCreateIdentity(fs::path(argv[2])).fingerprint().c_str());
        return 0;
    }
    if (argc < 5 || std::strcmp(argv[1], "--state") != 0
        || std::strcmp(argv[3], "--server-card") != 0) {
        printUsage();
        return 2;
    }

    const fs::path stateDir(argv[2]);
    const fs::path cardPath(argv[4]);
    std::string host = kDefaultHost;
    int port = kDefaultPort;
    std::string portalHost;
    int portalPort = 0;
    fs::path configPath;
    std::string messagingHost;
    int messagingPort = 0;
    std::vector<std::string> operatorFingerprints;
    bazarish::log::Level logLevel = bazarish::log::Level::eInfo;
    for (int i = 5; i < argc;) {
        const std::string flag = argv[i];
        if (flag == "--listen" && i + 2 < argc) {
            host = argv[i + 1];
            port = std::atoi(argv[i + 2]);
            i += 3;
        } else if (flag == "--portal-listen" && i + 2 < argc) {
            portalHost = argv[i + 1];
            portalPort = std::atoi(argv[i + 2]);
            i += 3;
        } else if (flag == "--config" && i + 1 < argc) {
            configPath = argv[i + 1];
            i += 2;
        } else if (flag == "--messaging" && i + 2 < argc) {
            messagingHost = argv[i + 1];
            messagingPort = std::atoi(argv[i + 2]);
            i += 3;
        } else if (flag == "--operator-fingerprint" && i + 1 < argc) {
            operatorFingerprints.emplace_back(argv[i + 1]);
            i += 2;
        } else if (flag == "--log-level" && i + 1 < argc) {
            const std::optional<bazarish::log::Level> parsed
                = bazarish::log::levelFromString(argv[i + 1]);
            if (!parsed.has_value()) {
                printUsage();
                return 2;
            }
            logLevel = parsed.value();
            i += 2;
        } else {
            printUsage();
            return 2;
        }
    }

    bazarish::log::setComponent("service-node");
    bazarish::log::setLevel(logLevel);

    const bazarish::Bytes cardDer = readFileBytes(cardPath);
    const bazarish::ServerCard card = bazarish::ServerCard::verify(cardDer);

    // Payments/paid-services config (a single source feeding both the discovery
    // advertisement and the buy endpoints); dev defaults when no file is given.
    const NodeConfig nodeConfig
        = configPath.empty() ? NodeConfig{} : loadNodeConfig(configPath);

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
        portalOptions.registrationMessage = nodeConfig.registration.message;
        portal = std::make_unique<bazarish::service::PortalApi>(portalOptions, *captcha, grants);
        portalThread = std::thread(
            [portalHost, portalPort]() { portal->listen(portalHost, portalPort); });
        portalThread.detach();
        bazarish::log::info("portal on {}:{}", portalHost, portalPort);
    }

    // A moderated node accumulates accounts nobody ever approves. Sweep them so a
    // dead registration does not sit there forever holding a fingerprint.
    static std::thread sweepThread;
    if (nodeConfig.registration.requireApproval && nodeConfig.registration.ttlDays > 0) {
        const std::int64_t ttlSeconds = nodeConfig.registration.ttlDays * 24 * 3600;
        sweepThread = std::thread([&grants, &store, ttlSeconds]() {
            while (true) {
                std::this_thread::sleep_for(std::chrono::hours(1));
                const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
                for (const std::string& user : grants.pendingUsers()) {
                    const std::optional<bazarish::service::GrantStore::Approval> approval
                        = grants.peekApproval(user);
                    if (!approval.has_value() || approval->requestedAt + ttlSeconds > now) {
                        continue;
                    }
                    grants.erase(user);
                    store.deleteSubscription(user);
                    bazarish::log::info("swept never-approved account {}", user.substr(0, 12));
                }
            }
        });
        sweepThread.detach();
        bazarish::log::info("registration requires approval; unapproved accounts expire in {} days",
            nodeConfig.registration.ttlDays);
    }

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
