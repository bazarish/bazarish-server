// Bazarish project (c) 2026
#include "Gateway.hpp"
#include "Settings.hpp"

#include <Restart.hpp>

#include <bazarish/ConfigFile.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Log.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <thread>

namespace {

constexpr std::chrono::seconds kRouterWarmup{120};
constexpr std::chrono::milliseconds kRestartAnswerGrace{300};

volatile std::sig_atomic_t g_stop = 0;

void onSignal(const int)
{
    g_stop = 1;
}

void printUsage()
{
    std::printf("bazarish-gateway %s\n"
                "Usage: bazarish-gateway --config <path>\n"
                "       bazarish-gateway --version\n"
                "\n"
                "Runs an I2P router for clients that do not run one. A client\n"
                "reaches it over one WebSocket per flow at a secret path,\n"
                "carrying a static token; everything else on this listener is a\n"
                "404 from one template.\n"
                "\n"
                "\"basePath\" and \"token\" are mandatory and have no defaults: a\n"
                "gateway that came up without them would be one anybody could\n"
                "walk into. TLS, the public address and the cover site belong to\n"
                "the front this listens behind. \"operators\" names who may use\n"
                "\"opsListen\": health, settings and restart. The README has the rest.\n",
        bazarish::gateway::kVersion);
}

}  // namespace

int main(const int argc, const char** argv)
{
    if (argc == 2 && std::strcmp(argv[1], "--version") == 0) {
        std::printf("bazarish-gateway %s\n", bazarish::gateway::kVersion);
        return 0;
    }
    if (argc != 3 || std::strcmp(argv[1], "--config") != 0) {
        printUsage();
        return 2;
    }

    bazarish::gateway::Settings settings;
    try {
        const bazarish::ConfigView config(
            bazarish::ConfigFile(std::filesystem::path(argv[2])).read());
        settings = bazarish::gateway::Settings::from(config);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "config: %s\n", error.what());
        return 2;
    }

    std::filesystem::create_directories(settings.stateDir);
    bazarish::i2p::RouterConfig routerConfig;
    routerConfig.dataDir = settings.stateDir / "i2p";
    routerConfig.role = bazarish::i2p::Role::eClient;
    routerConfig.reseedUrls = settings.reseedUrls;

    bazarish::i2p::Router router(routerConfig);
    router.start();
    bazarish::log::info("gateway: router {} starting", bazarish::i2p::routerVersion());

    std::atomic<bool> restartWanted{false};
    bazarish::gateway::Gateway gateway(settings, router,
        bazarish::gateway::OpsControl{
            std::filesystem::path(argv[2]), [&restartWanted]() { restartWanted = true; }});
    const int port = gateway.start();
    std::printf("bazarish-gateway %s listening on %s:%d\n", bazarish::gateway::kVersion, settings.listenHost.c_str(),
        port);
    std::fflush(stdout);

    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);

    const auto warm = std::chrono::steady_clock::now() + kRouterWarmup;
    bool announced = false;
    while (g_stop == 0 && !restartWanted) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (!announced && router.ready()) {
            bazarish::log::info("gateway: the router has tunnels");
            announced = true;
        }
        if (!announced && std::chrono::steady_clock::now() > warm) {
            bazarish::log::warn("gateway: the router still has no tunnels");
            announced = true;
        }
    }

    if (restartWanted) {
        // The handler that asked has to get its answer out before the ops socket closes.
        std::this_thread::sleep_for(kRestartAnswerGrace);
    }
    bazarish::log::info("gateway: stopping");
    gateway.stop();
    router.stop();
    return restartWanted ? bazarish::kRestartExitCode : 0;
}
