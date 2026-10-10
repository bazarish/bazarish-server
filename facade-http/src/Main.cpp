// Bazarish project (c) 2026
#include "Facade.hpp"
#include "FacadeAddress.hpp"
#include "I2pFront.hpp"

#include <bazarish/ConfigFile.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Tls.hpp>
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
constexpr int kDefaultTunnelQuantity = 16;

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
        "The facade's own I2P destination is how clients reach the API, and the\n"
        "only way: \"listen\" is the socket it relays to, kept on loopback.\n"
        "Its address is that destination plus a secret path every request starts\n"
        "with; both are minted at the first start and kept in \"state\", because\n"
        "the address travels in the server descriptor. The admin panel replaces\n"
        "both at once.\n"
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
    const std::optional<bazarish::ConfigView::Endpoint> direct
        = config.endpoint("directListen");
    const std::filesystem::path stateDir(config.text("state"));
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
        config.number("i2p.tunnelQuantity", kDefaultTunnelQuantity));
    if (tunnelQuantity < 1 || tunnelQuantity > bazarish::i2p::kMaxTunnelQuantity) {
        std::fprintf(stderr, "config: i2p.tunnelQuantity is between 1 and %d\n",
            bazarish::i2p::kMaxTunnelQuantity);
        return 2;
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

    bazarish::facade::FacadeOptions options;
    options.version = kVersion;
    options.operatorFingerprints = config.list("operators");
    if (const std::optional<bazarish::ConfigView::Endpoint> messaging
        = config.endpoint("messaging");
        messaging.has_value()) {
        options.messagingHost = messaging->host;
        options.messagingPort = messaging->port;
        options.messagingPin = config.text("messaging.pin");
    }

    if (config.has("basePath")) {
        std::fprintf(stderr, "config: \"basePath\" is no longer read: the secret path lives in\n"
                             "\"state\" beside the destination key\n");
        return 2;
    }
    if (stateDir.empty()) {
        std::fprintf(stderr, "config: \"state\" is mandatory: the destination key must"
                             " persist,\nits address travels in the server descriptor\n");
        return 2;
    }
    std::optional<bazarish::facade::FacadeAddress> address;
    try {
        address = bazarish::facade::loadAddress(stateDir);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "state: %s\n", error.what());
        return 2;
    }
    options.basePath = address->basePath;
    options.url = address->url();

    bazarish::log::setComponent("facade-http");
    bazarish::log::setLevel(logLevel);

    bazarish::facade::FacadeSettings::Values settingValues;
    settingValues.logLevel = config.text("logLevel").empty() ? "info" : config.text("logLevel");
    settingValues.messagingHost = options.messagingHost;
    settingValues.messagingPort = options.messagingPort;
    settingValues.listenHost = listen.host;
    settingValues.listenPort = listen.port;
    settingValues.opsHost = ops.has_value() ? ops->host : std::string();
    settingValues.opsPort = ops.has_value() ? ops->port : 0;
    settingValues.directHost = direct.has_value() ? direct->host : std::string();
    settingValues.directPort = direct.has_value() ? direct->port : 0;
    settingValues.i2pPrivacy = std::string(bazarish::i2p::privacyName(privacy));
    settingValues.i2pTunnelQuantity = tunnelQuantity;
    options.settings = std::make_shared<bazarish::facade::FacadeSettings>(
        std::filesystem::path(argv[2]), settingValues);
    options.stateDirectory = stateDir.string();
    const bazarish::tls::Credential credential = bazarish::tls::selfSigned(stateDir);
    options.tlsCertificate = credential.certificate.string();
    options.tlsKey = credential.key.string();
    options.opsClientPins = config.list("opsClients");
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
    std::printf("facade socket pin: %s\n", credential.pin.c_str());
    std::fflush(stdout);
    bazarish::log::info("messaging -> {}:{}", options.messagingHost, options.messagingPort);

    if (ops.has_value()) {
        if (facade.bindOps(ops->host, ops->port) <= 0) {
            bazarish::log::error("failed to listen on {}:{} (ops)", ops->host, ops->port);
            return 1;
        }
        bazarish::log::info("ops listening on {}:{}", ops->host, ops->port);
    }

    if (direct.has_value()) {
        if (facade.bindDirect(direct->host, direct->port) <= 0) {
            bazarish::log::error(
                "failed to listen on {}:{} (direct)", direct->host, direct->port);
            return 1;
        }
        bazarish::log::info("direct listening on {}:{}", direct->host, direct->port);
    }

    bazarish::log::info("listening on {}:{}{}", listen.host, listen.port, options.basePath);
    if (facade.bind(listen.host, listen.port) <= 0) {
        bazarish::log::error("failed to listen on {}:{}", listen.host, listen.port);
        return 1;
    }

    bazarish::facade::I2pFront::Options frontOptions;
    frontOptions.stateDir = stateDir;
    frontOptions.localHost = listen.host == "0.0.0.0" ? std::string("127.0.0.1") : listen.host;
    frontOptions.localPort = listen.port;
    frontOptions.privacy = privacy;
    frontOptions.tunnelQuantity = tunnelQuantity;
    bazarish::facade::I2pFront i2pFront(frontOptions, address->keys);
    bazarish::log::info("building the I2P destination for the facade API...");
    i2pFront.start();
    std::printf("i2p facade: %s\n", options.url.c_str());
    std::fflush(stdout);

    facade.wait();
    i2pFront.stop();
    facade.stop();
    return restart.requested() ? bazarish::kRestartExitCode : 0;
}
