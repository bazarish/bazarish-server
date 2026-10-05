// Bazarish project (c) 2026
#include "Facade.hpp"
#include "I2pFront.hpp"

#include <bazarish/ConfigFile.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Log.hpp>
#include <Restart.hpp>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>

namespace {

constexpr const char* kVersion = "0.0.1";
constexpr const char* kDefaultHost = "127.0.0.1";
constexpr int kDefaultPort = 8419;

void printUsage()
{
    std::printf(
        "bazarish-facade-http %s\n"
        "Usage: bazarish-facade-http --config <path>\n"
        "       bazarish-facade-http --version\n"
        "\n"
        "Forwards two requests to the messaging server - the sealed client tunnel\n"
        "and the public server card - and answers everything else with a bare 404.\n"
        "Everything it runs on is in the config file.\n"
        "\n"
        "\"basePath\" is mandatory: it is the only thing standing between a scan of\n"
        "the host and the clearnet API, and it reaches a client only inside the\n"
        "facade URL of the server descriptor. Set \"public\": true instead solely\n"
        "when a fronting proxy already publishes this facade under a secret URI.\n"
        "\"i2p\" publishes the same API on the facade's own destination(s) - the\n"
        "preferred way in: clients reach it without touching the clearnet at all.\n"
        "The keys live in \"state\" and the addresses are stable across restarts,\n"
        "because they travel in the server descriptor.\n"
        "\"opsListen\" adds a private socket serving the operator-signed health,\n"
        "settings and restart for the admin panel; it is never published to clients.\n",
        kVersion);
}

}  // namespace

int main(const int argc, const char** argv)
{
    if (argc == 2 && std::strcmp(argv[1], "--version") == 0) {
        std::printf("bazarish-facade-http %s\n", kVersion);
        return 0;
    }

    if (argc != 3 || std::strcmp(argv[1], "--config") != 0) {
        printUsage();
        return 2;
    }
    bazarish::ConfigView config(nlohmann::json::object());
    try {
        config = bazarish::ConfigView(bazarish::ConfigFile(std::filesystem::path(argv[2])).read());
    } catch (const std::exception& error) {
        std::fprintf(stderr, "config: %s\n", error.what());
        return 2;
    }

    const bazarish::ConfigView::Endpoint listen = config.endpoint("listen").value_or(
        bazarish::ConfigView::Endpoint{kDefaultHost, kDefaultPort});
    const std::optional<bazarish::ConfigView::Endpoint> ops = config.endpoint("opsListen");
    const bool servePublicRoot = config.flag("public", false);
    const bool enableI2p = config.flag("i2p.enabled", false);
    const std::filesystem::path stateDir(config.text("state"));
    const std::size_t i2pDests = static_cast<std::size_t>(config.number("i2p.destinations", 1));
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
        config.number("i2p.tunnelQuantity", bazarish::i2p::kDefaultTunnelQuantity));
    bazarish::log::Level logLevel = bazarish::log::Level::eInfo;
    if (const std::string level = config.text("logLevel"); !level.empty()) {
        const std::optional<bazarish::log::Level> parsed = bazarish::log::levelFromString(level);
        if (!parsed.has_value()) {
            std::fprintf(stderr, "config: logLevel is not a level\n");
            return 2;
        }
        logLevel = *parsed;
    }

    bazarish::facade::FacadeOptions options;
    options.version = kVersion;
    options.basePath = config.text("basePath");
    options.operatorFingerprints = config.list("operators");
    if (const std::optional<bazarish::ConfigView::Endpoint> messaging
        = config.endpoint("messaging");
        messaging.has_value()) {
        options.messagingHost = messaging->host;
        options.messagingPort = messaging->port;
    }

    if (options.basePath.empty() && !servePublicRoot) {
        std::fprintf(stderr,
            "the clearnet API must not be reachable without a secret prefix: set\n"
            "\"basePath\", or \"public\": true when a fronting proxy owns the secret\n");
        return 2;
    }
    if (!options.basePath.empty() && servePublicRoot) {
        std::fprintf(stderr, "config: \"public\" and \"basePath\" contradict each other\n");
        return 2;
    }
    if (!options.basePath.empty() && !bazarish::facade::isValidBasePath(options.basePath)) {
        std::fprintf(stderr,
            "config: \"basePath\" is an absolute prefix such as /h9fd/kshdcy,\n"
            "with no trailing slash and no query\n");
        return 2;
    }
    if (enableI2p && stateDir.empty()) {
        std::fprintf(stderr, "config: \"i2p\" needs \"state\": the destination keys must"
                             " persist,\ntheir addresses travel in the server descriptor\n");
        return 2;
    }
    if (i2pDests == 0) {
        std::fprintf(stderr, "config: \"i2p.destinations\" is at least 1\n");
        return 2;
    }

    bazarish::log::setComponent("facade-http");
    bazarish::log::setLevel(logLevel);

    bazarish::facade::FacadeSettings::Values settingValues;
    settingValues.logLevel = config.text("logLevel").empty() ? "info" : config.text("logLevel");
    settingValues.basePath = options.basePath;
    settingValues.messagingHost = options.messagingHost;
    settingValues.messagingPort = options.messagingPort;
    settingValues.listenHost = listen.host;
    settingValues.listenPort = listen.port;
    settingValues.opsHost = ops.has_value() ? ops->host : std::string();
    settingValues.opsPort = ops.has_value() ? ops->port : 0;
    settingValues.i2pEnabled = enableI2p;
    settingValues.i2pDestinations = static_cast<int>(i2pDests);
    settingValues.i2pPrivacy = std::string(bazarish::i2p::privacyName(privacy));
    settingValues.i2pTunnelQuantity = tunnelQuantity;
    options.settings = std::make_shared<bazarish::facade::FacadeSettings>(
        std::filesystem::path(argv[2]), settingValues);
    options.stateDirectory = stateDir.string();
    const auto restartHook = std::make_shared<std::function<void()>>();
    options.requestRestart = [restartHook]() {
        if (*restartHook) {
            (*restartHook)();
        }
    };

    bazarish::facade::Facade facade(options);

    bazarish::RestartSwitch restart([&facade]() { facade.stop(); });
    *restartHook = [&restart]() { restart.request(); };
    std::printf("bazarish-facade-http %s\n", kVersion);
    std::fflush(stdout);
    bazarish::log::info("messaging -> {}:{}", options.messagingHost, options.messagingPort);

    if (ops.has_value()) {
        if (facade.bindOps(ops->host, ops->port) <= 0) {
            bazarish::log::error("failed to listen on {}:{} (ops)", ops->host, ops->port);
            return 1;
        }
        bazarish::log::info("ops listening on {}:{}", ops->host, ops->port);
    }

    bazarish::log::info("listening on {}:{}{}", listen.host, listen.port,
        options.basePath.empty() ? " (no secret prefix: fronting proxy owns it)"
                                 : options.basePath);
    if (facade.bind(listen.host, listen.port) <= 0) {
        bazarish::log::error("failed to listen on {}:{}", listen.host, listen.port);
        return 1;
    }

    std::unique_ptr<bazarish::facade::I2pFront> i2pFront;
    if (enableI2p) {
        bazarish::facade::I2pFront::Options frontOptions;
        frontOptions.stateDir = stateDir;
        frontOptions.localHost
            = listen.host == "0.0.0.0" ? std::string("127.0.0.1") : listen.host;
        frontOptions.localPort = listen.port;
        frontOptions.destinations = i2pDests;
        frontOptions.privacy = privacy;
        frontOptions.tunnelQuantity = tunnelQuantity;
        i2pFront = std::make_unique<bazarish::facade::I2pFront>(frontOptions);
        bazarish::log::info("building I2P destination(s) for the facade API...");
        for (const std::string& address : i2pFront->start()) {
            std::printf("i2p facade: http://%s%s\n", address.c_str(), options.basePath.c_str());
        }
        std::fflush(stdout);
    }

    facade.wait();
    i2pFront.reset();
    facade.stop();
    return restart.requested() ? bazarish::kRestartExitCode : 0;
}
