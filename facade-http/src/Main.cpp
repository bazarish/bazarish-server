// Bazarish project (c) 2026
#include "Facade.hpp"

#include <FleetPorts.hpp>
#include <OpsSettings.hpp>
#include <Restart.hpp>

#include "FacadeAddress.hpp"
#include "I2pFront.hpp"
#include <CommandLine.hpp>

#include <BuildVersion.hpp>
#include <bazarish/ConfigFile.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Tls.hpp>

#include <cstdio>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <variant>

namespace {

constexpr const char* kDefaultHost = bazarish::fleet::kLoopback;
constexpr int kDefaultPort = bazarish::fleet::kFacadePort;
constexpr int kDefaultTunnelQuantity = 16;

void printUsage()
{
    std::printf(
        "bazarish-facade-http %s\n"
        "Usage: bazarish-facade-http --config <path>\n"
        "       bazarish-facade-http --version\n"
        "\n"
        "Forwards the sealed client tunnel and the public card of two backends - the\n"
        "messaging server (\"messaging\") and the service node (\"serviceNode\") - and\n"
        "the service node's login callback and /login/c/<nonce>; everything else is a\n"
        "bare 404. Everything it runs on is in the config file.\n"
        "\n"
        "Clients reach it through its own I2P destination: \"listen\" is the socket it\n"
        "relays to, kept on loopback. Its address is that destination, answered at /;\n"
        "the key is minted at the first start and kept in \"state\", because the\n"
        "address travels in the server descriptor. The admin panel can replace it.\n"
        "\"directListen\" serves the same over TLS to a gateway given a route here.\n"
        "\"opsListen\" adds a private socket serving the operator-signed health,\n"
        "settings and restart for the admin panel; it is never published to clients.\n",
        bazarish::kBuildVersion);
}

}  // namespace

int main(const int argc, const char** argv)
{
    const std::variant<std::filesystem::path, int> argument = bazarish::server::configArgument(
        argc, argv, std::string("bazarish-facade-http ") + bazarish::kBuildVersion, printUsage);
    if (const int* const status = std::get_if<int>(&argument)) {
        return *status;
    }
    const std::filesystem::path configPath = std::get<std::filesystem::path>(argument);
    bazarish::ConfigView config(nlohmann::json::object());
    try {
        config = bazarish::ConfigView(bazarish::ConfigFile(configPath).read());
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
    bazarish::log::Level logLevel = bazarish::log::Level::eInfo;
    try {
        privacy = bazarish::server::configPrivacy(config, bazarish::i2p::Privacy::eMax);
        logLevel = bazarish::server::configLogLevel(config);
    } catch (const std::invalid_argument& error) {
        std::fprintf(stderr, "config: %s\n", error.what());
        return 2;
    }
    const int tunnelQuantity = static_cast<int>(
        config.number("i2p.tunnelQuantity", kDefaultTunnelQuantity));
    if (tunnelQuantity < 1 || tunnelQuantity > bazarish::i2p::kMaxTunnelQuantity) {
        std::fprintf(stderr, "config: i2p.tunnelQuantity is between 1 and %d\n",
            bazarish::i2p::kMaxTunnelQuantity);
        return 2;
    }

    bazarish::facade::FacadeOptions options;
    options.version = bazarish::kBuildVersion;
    options.operatorFingerprints = config.list("operators");
    const auto readUpstream = [&config](
                                  const std::string& key, bazarish::facade::Upstream& upstream) {
        if (const std::optional<bazarish::ConfigView::Endpoint> named = config.endpoint(key);
            named.has_value()) {
            upstream.host = named->host;
            upstream.port = named->port;
            upstream.pin = config.text(key + ".pin");
        }
    };
    readUpstream("messaging", options.messaging);
    readUpstream("serviceNode", options.serviceNode);

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
    options.address = address->address();

    bazarish::log::setComponent("facade-http");
    bazarish::log::setLevel(logLevel);

    bazarish::facade::FacadeSettings::Values settingValues;
    settingValues.logLevel = config.text("logLevel").empty() ? "info" : config.text("logLevel");
    settingValues.messagingHost = options.messaging.host;
    settingValues.messagingPort = options.messaging.port;
    settingValues.serviceNodeHost = options.serviceNode.host;
    settingValues.serviceNodePort = options.serviceNode.port;
    settingValues.listenHost = listen.host;
    settingValues.listenPort = listen.port;
    settingValues.opsHost = ops.has_value() ? ops->host : std::string();
    settingValues.opsPort = ops.has_value() ? ops->port : 0;
    settingValues.directHost = direct.has_value() ? direct->host : std::string();
    settingValues.directPort = direct.has_value() ? direct->port : 0;
    settingValues.i2pPrivacy = std::string(bazarish::i2p::privacyName(privacy));
    settingValues.i2pTunnelQuantity = tunnelQuantity;
    options.settings = std::make_shared<bazarish::facade::FacadeSettings>(
        configPath, settingValues);
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
    std::printf("bazarish-facade-http %s\n", bazarish::kBuildVersion);
    std::printf("facade socket pin: %s\n", credential.pin.c_str());
    std::fflush(stdout);
    bazarish::log::info("messaging -> {}:{}", options.messaging.host, options.messaging.port);
    bazarish::log::info(
        "service node -> {}:{}", options.serviceNode.host, options.serviceNode.port);

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

    bazarish::log::info("listening on {}:{}", listen.host, listen.port);
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
    std::printf("i2p facade: %s\n", options.address.c_str());
    std::fflush(stdout);

    facade.wait();
    i2pFront.stop();
    return restart.requested() ? bazarish::kRestartExitCode : 0;
}
