// Bazarish project (c) 2026
#include "Config.hpp"
#include "HttpApi.hpp"
#include "PanelSettings.hpp"
#include <CommandLine.hpp>

#include <BuildVersion.hpp>
#include <Restart.hpp>
#include <StateIdentity.hpp>

#include <bazarish/Crypto.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Tls.hpp>

#include <cstdio>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>

namespace {

namespace fs = std::filesystem;


void printUsage()
{
    std::printf(
        "bazarish-admin-panel %s\n"
        "Usage: bazarish-admin-panel --config <path>\n"
        "       bazarish-admin-panel --version\n"
        "\n"
        "Monitors and manages Bazarish services from one web interface. The panel\n"
        "signs every service call with its own identity (kept in <state>); put the\n"
        "printed fingerprint in each service's \"operators\" list. Sign in by signing\n"
        "the panel's challenge in your client; only an admin identity named in the\n"
        "config may sign in, and no backend needs to be online to log in.\n",
        bazarish::kBuildVersion);
}

}  // namespace

int main(const int argc, const char** argv)
{
    using namespace bazarish::admin;

    const std::variant<std::filesystem::path, int> argument = bazarish::server::configArgument(
        argc, argv, std::string("bazarish-admin-panel ") + bazarish::kBuildVersion, printUsage);
    if (const int* const status = std::get_if<int>(&argument)) {
        return *status;
    }
    const std::filesystem::path configPath = std::get<std::filesystem::path>(argument);

    Config config;
    try {
        config = Config::fromFile(configPath.string());
    } catch (const std::exception& error) {
        std::fprintf(stderr, "config: %s\n", error.what());
        return 2;
    }
    if (config.stateDir.empty() || config.assetsDir.empty()) {
        std::fprintf(stderr, "config: \"state\" and \"assets\" are required\n");
        return 2;
    }

    fs::create_directories(config.stateDir);
    const bazarish::Identity identity
        = bazarish::server::loadOrCreateIdentity(config.stateDir);
    const std::string host = config.listenHost;
    const int port = config.listenPort;

    HttpApiOptions options;
    options.version = bazarish::kBuildVersion;
    options.assetsDirectory = config.assetsDir;
    const bool unclaimed = config.admins.empty();
    const bazarish::tls::Credential credential = bazarish::tls::selfSigned(config.stateDir);
    const auto settings
        = std::make_shared<PanelSettings>(fs::path(configPath), std::move(config));
    const auto restartHook = std::make_shared<std::function<void()>>();
    options.requestRestart = [restartHook]() {
        if (*restartHook) {
            (*restartHook)();
        }
    };
    std::optional<HttpApi> api;
    try {
        api.emplace(settings, identity, credential, options);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "panel not started: %s\n", error.what());
        return 2;
    }

    std::printf("bazarish-admin-panel %s\n", bazarish::kBuildVersion);
    std::printf("panel operator fingerprint: %s\n", identity.fingerprint().c_str());
    std::printf("put this fingerprint in each service's \"operators\" list\n");
    std::printf("panel socket pin: %s\n", credential.pin.c_str());
    std::printf("put this pin in each service's \"opsClients\" list\n");
    std::printf("listening on %s:%d\n", host.c_str(), port);
    std::fflush(stdout);
    if (unclaimed) {
        bazarish::log::warn("no administrator yet: open http://{}:{}/setup and sign in - the first"
                            " key to sign there administers this panel",
            host, port);
    }

    bazarish::RestartSwitch restart([&api]() { api->stop(); });
    *restartHook = [&restart]() { restart.request(); };

    if (api->bind(host, port) <= 0) {
        if (restart.requested()) {
            return bazarish::kRestartExitCode;
        }
        std::fprintf(stderr, "failed to listen on %s:%d\n", host.c_str(), port);
        return 1;
    }
    api->wait();
    return restart.requested() ? bazarish::kRestartExitCode : 0;
}
