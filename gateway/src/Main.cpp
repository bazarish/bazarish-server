// Bazarish project (c) 2026
#include "Gateway.hpp"
#include "Settings.hpp"
#include <CommandLine.hpp>
#include <LogRing.hpp>

#include <BuildVersion.hpp>
#include <Restart.hpp>

#include <bazarish/ConfigFile.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Log.hpp>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <variant>
#include <string>

namespace {

constexpr std::chrono::seconds kRouterWarmup{120};

void printUsage()
{
    std::printf("bazarish-gateway %s\n"
                "Usage: bazarish-gateway --config <path>\n"
                "       bazarish-gateway --version\n"
                "\n"
                "Runs an I2P router for clients that do not run one. A client\n"
                "reaches it over one WebSocket per flow at a secret path, in a\n"
                "channel sealed to this gateway's key; everything else on this\n"
                "listener is a 404 from one template.\n"
                "\n"
                "\"basePath\" is mandatory and has no default: a gateway that came\n"
                "up without it would be one anybody could walk into. The key and\n"
                "its fingerprint live in \"state\". TLS, the public address and\n"
                "the cover site belong to the front this listens behind.\n"
                "\"operators\" names who may use \"opsListen\": health, settings\n"
                "and restart. The README has the rest.\n",
        bazarish::kBuildVersion);
}

}  // namespace

int main(const int argc, const char** argv)
{
    const std::variant<std::filesystem::path, int> argument = bazarish::server::configArgument(
        argc, argv, std::string("bazarish-gateway ") + bazarish::kBuildVersion, printUsage);
    if (const int* const status = std::get_if<int>(&argument)) {
        return *status;
    }
    const std::filesystem::path configPath = std::get<std::filesystem::path>(argument);

    bazarish::gateway::Settings settings;
    try {
        const bazarish::ConfigView config(
            bazarish::ConfigFile(configPath).read());
        settings = bazarish::gateway::Settings::from(config);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "config: %s\n", error.what());
        return 2;
    }

    bazarish::log::setComponent("gateway");
    bazarish::log::setLevel(settings.logLevel);
    const auto logRing = std::make_shared<bazarish::server::LogRing>();
    const bazarish::server::LogCapture logCapture(logRing);

    bazarish::StopGate stopped;
    const bazarish::SignalWaiter signalWaiter([&stopped]() { stopped.stop(); });

    std::filesystem::create_directories(settings.stateDir);
    bazarish::i2p::RouterConfig routerConfig;
    routerConfig.dataDir = settings.stateDir / "i2p";
    routerConfig.role = bazarish::i2p::Role::eClient;
    routerConfig.reseedUrls = settings.reseedUrls;

    bazarish::i2p::Router router(routerConfig);
    router.start();
    bazarish::log::info("router {} starting", bazarish::i2p::routerVersion());

    bazarish::RestartSwitch restart([&stopped]() { stopped.stop(); });
    bazarish::gateway::Gateway gateway(settings, router,
        bazarish::gateway::OpsControl{
            configPath, [&restart]() { restart.request(); }, logRing});
    const int port = gateway.start();
    std::printf("bazarish-gateway %s listening on %s:%d\n", bazarish::kBuildVersion, settings.listenHost.c_str(),
        port);
    std::fflush(stdout);

    if (!stopped.waitFor(kRouterWarmup)) {
        if (router.ready()) {
            bazarish::log::info("the router has tunnels");
        } else {
            bazarish::log::warn("the router still has no tunnels");
        }
        stopped.wait();
    }

    bazarish::log::info("stopping");
    gateway.stop();
    router.stop();
    return restart.requested() ? bazarish::kRestartExitCode : 0;
}
