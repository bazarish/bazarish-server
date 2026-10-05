// Bazarish project (c) 2026
#include "DeliveryEngine.hpp"
#include "DiskStorage.hpp"
#include <RateLimiter.hpp>
#include "EventGate.hpp"
#include "HttpApi.hpp"
#include "PerUserDestinations.hpp"

#include <bazarish/Certificates.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/ConfigFile.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/PrivateFile.hpp>
#include <Restart.hpp>

#include <bazarish/HttpClient.hpp>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

namespace fs = std::filesystem;

constexpr const char* kVersion = "0.0.2";
constexpr const char* kDefaultHost = "127.0.0.1";
constexpr int kDefaultPort = 8420;
constexpr int kServiceNodeTimeoutSeconds = 5;
constexpr std::int64_t kCardCacheSeconds = 60;

void printUsage()
{
    std::printf(
        "bazarish-server %s\n"
        "Usage: bazarish-server --config <path>\n"
        "       bazarish-server --version\n"
        "\n"
        "Everything this server runs on is in the config file - state directory,\n"
        "listen address, operator fingerprints, I2P settings, limits - so there is\n"
        "one place to look and one place to change. The state directory holds the\n"
        "server keys and the content storage; keys are generated on first start,\n"
        "and the server card is always written to <state>/server-card.der.\n"
        "\n"
        "The server keeps no destination of its own: inbound federation arrives on\n"
        "each user's own I2P destination, which it operates from the transient that\n"
        "user delegated to it. Clients reach this server through a facade.\n",
        kVersion);
}

using bazarish::nowSeconds;
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

bazarish::Key loadOrCreateSealingKey(const fs::path& stateDir)
{
    const fs::path path = stateDir / "sealing.pem";
    if (fs::exists(path)) {
        return bazarish::Key::fromPrivatePem(readFileText(path));
    }
    bazarish::Key key = bazarish::Key::generateSealing();
    writePrivateFile(path, key.privatePem());
    return key;
}

}  // namespace

int main(const int argc, const char** argv)
{
    if (argc == 2 && std::strcmp(argv[1], "--version") == 0) {
        std::printf("bazarish-server %s\n", kVersion);
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
    if (!config.flag("i2p.enabled", true)) {
        std::fprintf(stderr,
            "I2P federation is required: \"i2p\": {\"enabled\": false} is not a server this "
            "protocol can run (delivery is routed by I2P destination).\n");
        return 2;
    }
    bazarish::server::DeliveryEngineOptions engineOptions;
    const std::vector<std::string> operatorFingerprints = config.list("operators");
    const std::string serviceNodeUrl = config.text("serviceNode");
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
    const int tunnelQuantity = static_cast<int>(
        config.number("i2p.tunnelQuantity", bazarish::i2p::kMaxTunnelQuantity));
    if (tunnelQuantity < 1 || tunnelQuantity > bazarish::i2p::kMaxTunnelQuantity) {
        std::fprintf(stderr, "config: i2p.tunnelQuantity is between 1 and %d\n",
            bazarish::i2p::kMaxTunnelQuantity);
        return 2;
    }
    const std::size_t federationRateLimit
        = static_cast<std::size_t>(config.number("federationRateLimit", 240));
    constexpr std::int64_t kFederationRateWindowSeconds = bazarish::kSecondsPerMinute;
    const std::int64_t mailboxRetentionDays = config.number("mailboxRetentionDays", 30);
    bazarish::log::Level logLevel = bazarish::log::Level::eInfo;
    if (const std::string level = config.text("logLevel"); !level.empty()) {
        const std::optional<bazarish::log::Level> parsed = bazarish::log::levelFromString(level);
        if (!parsed.has_value()) {
            std::fprintf(stderr, "config: logLevel is not a level\n");
            return 2;
        }
        logLevel = *parsed;
    }
    // libi2pd's own logging is off by default; the config turns it on for debugging.
    const bool i2pLog = config.flag("i2p.log", false);

    bazarish::log::setComponent("server-core");
    bazarish::log::setLevel(logLevel);
    // Route libi2pd's own logs into our log only when explicitly requested.
    if (i2pLog) {
        bazarish::i2p::setI2pLogging(true);
    }

    fs::create_directories(stateDir);
    const auto identity = std::make_shared<const bazarish::Identity>(
        loadOrCreateIdentity(stateDir));
    const auto sealing = std::make_shared<bazarish::Key>(loadOrCreateSealingKey(stateDir));
    if (!sealing->hasKem()) {
        std::fprintf(stderr,
            "%s holds a sealing key with no ML-KEM half - it was made before sealing keys\n"
            "were hybrid, and no client can open a tunnel to it. Move it aside and start\n"
            "again: a new one is generated, and nothing is stored under the old one (the\n"
            "mail in the mailboxes is sealed to its owners' keys, not to this).\n",
            (stateDir / "sealing.pem").string().c_str());
        return 1;
    }

    bazarish::server::DiskStorage storage(stateDir / "storage");
    bazarish::server::EventGate eventGate;
    engineOptions.onDelivered = [&eventGate](const std::string& user) { eventGate.notify(user); };
    bazarish::server::DeliveryEngine engine(
        storage, identity->fingerprint(), sealing, engineOptions);

    std::printf("bazarish-server %s\n", kVersion);
    std::printf("server fingerprint: %s\n", identity->fingerprint().c_str());
    std::fflush(stdout);

    std::unique_ptr<bazarish::i2p::Router> router;
    std::unique_ptr<bazarish::RateLimiter> federationLimiter;
    std::unique_ptr<bazarish::server::PerUserDestinations> perUserDests;
    {
        bazarish::log::info("starting embedded I2P router (building tunnels)...");
        bazarish::i2p::RouterConfig routerConfig;
        routerConfig.dataDir = stateDir / "i2p";
        routerConfig.role = bazarish::i2p::Role::eServer;
        router = std::make_unique<bazarish::i2p::Router>(routerConfig);

        if (federationRateLimit > 0) {
            federationLimiter = std::make_unique<bazarish::RateLimiter>(
                federationRateLimit, kFederationRateWindowSeconds);
        }

        bazarish::server::GetCardFn getCard;
        if (!serviceNodeUrl.empty()) {
            struct CardCache {
                std::mutex mutex;
                std::map<std::string, std::pair<std::int64_t, bazarish::Bytes>> entries;
            };
            const auto cache = std::make_shared<CardCache>();
            getCard = [serviceNodeUrl, cache](const std::string& fp,
                          const std::string& view) -> std::optional<bazarish::Bytes> {
                const std::string key = fp + "\n" + view;
                const std::int64_t now = nowSeconds();
                {
                    const std::lock_guard<std::mutex> lock(cache->mutex);
                    const auto found = cache->entries.find(key);
                    if (found != cache->entries.end()
                        && now - found->second.first < kCardCacheSeconds) {
                        return found->second.second;
                    }
                }
                const bazarish::http::Url node = bazarish::http::parseUrl(serviceNodeUrl);
                bazarish::http::ClientRequest lookup;
                lookup.method = "GET";
                lookup.target = "/v1/account/card?user=" + fp + "&view=" + view;
                bazarish::http::ClientOptions options;
                options.connectTimeout = std::chrono::seconds(kServiceNodeTimeoutSeconds);
                options.readTimeout = std::chrono::seconds(kServiceNodeTimeoutSeconds);
                options.writeTimeout = std::chrono::seconds(kServiceNodeTimeoutSeconds);
                const bazarish::http::ClientResponse res
                    = bazarish::http::request(node.host, node.port, lookup, options);
                if (res.status != 200) {
                    return std::nullopt;
                }
                try {
                    const nlohmann::json body = nlohmann::json::parse(res.body);
                    bazarish::Bytes card
                        = bazarish::fromBase64(body.at("card").get<std::string>());
                    const std::lock_guard<std::mutex> lock(cache->mutex);
                    cache->entries[key] = {now, card};
                    return card;
                } catch (const std::exception&) {
                    return std::nullopt;
                }
            };
        }

        perUserDests = std::make_unique<bazarish::server::PerUserDestinations>(
            router.get(), engine, stateDir, privacy, tunnelQuantity, federationLimiter.get());
        perUserDests->setGetCard(getCard);
        perUserDests->reloadPersisted(nowSeconds());
    }

    const bazarish::Bytes card = bazarish::ServerCard::issue(
        *identity, bazarish::Key::fromPublicDer(sealing->publicDer()), nowSeconds());
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
    httpOptions.version = kVersion;
    httpOptions.eventGate = &eventGate;
    httpOptions.defaultQuotaBytes = engineOptions.defaultQuotaBytes;
    httpOptions.mailboxRetentionSeconds
        = mailboxRetentionDays > 0 ? mailboxRetentionDays * bazarish::kSecondsPerDay : 0;
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
        return {assigned.dest, assigned.sealingKey, assigned.state};
    };
    {
        httpOptions.provisionI2pDest = [&perUserDests](const std::string& user,
                                           const std::string& transientB64,
                                           const std::int64_t expiresUnix) {
            perUserDests->provision(user, transientB64, expiresUnix);
        };
        httpOptions.revokeI2pDest = [&perUserDests](const std::string& user) {
            perUserDests->revoke(user);
        };
        httpOptions.prepareServingKey = [&perUserDests](const std::string& user) {
            return perUserDests->prepareServingKey(user);
        };
        httpOptions.commitServingKey = [&perUserDests](const std::string& user) {
            return perUserDests->commitServingKey(user);
        };
    }
    bazarish::server::ServerSettings::Values settingValues;
    settingValues.logLevel = config.text("logLevel").empty() ? "info" : config.text("logLevel");
    settingValues.i2pLog = i2pLog;
    settingValues.i2pPrivacy = bazarish::i2p::privacyName(privacy);
    settingValues.i2pTunnelQuantity = tunnelQuantity;
    settingValues.federationRateLimit = federationRateLimit;
    settingValues.mailboxRetentionDays = mailboxRetentionDays;
    settingValues.listenHost = host;
    settingValues.listenPort = port;
    settingValues.serviceNodeUrl = serviceNodeUrl;
    httpOptions.settings = std::make_shared<bazarish::server::ServerSettings>(
        fs::path(argv[2]), settingValues);
    httpOptions.stateDirectory = stateDir.string();
    httpOptions.fingerprint = identity->fingerprint();
    httpOptions.sealingKey = sealing;
    httpOptions.serverCardDer = card;
    httpOptions.identity = identity;
    httpOptions.serviceNodeUrl = serviceNodeUrl;
    const auto restartHook = std::make_shared<std::function<void()>>();
    httpOptions.requestRestart = [restartHook]() {
        if (*restartHook) {
            (*restartHook)();
        }
    };

    bazarish::server::HttpApi api(storage, httpOptions);

    bazarish::RestartSwitch restart([&api]() { api.stop(); });
    *restartHook = [&restart]() { restart.request(); };

    bazarish::log::info("listening on {}:{} (private channel for facades)", host, port);

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
