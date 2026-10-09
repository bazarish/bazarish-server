// Bazarish project (c) 2026
#include "Config.hpp"
#include "HttpApi.hpp"
#include "PanelSettings.hpp"

#include <Restart.hpp>

#include <bazarish/Crypto.hpp>
#include <bazarish/PrivateFile.hpp>
#include <bazarish/Tls.hpp>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace {

namespace fs = std::filesystem;

constexpr const char* kVersion = "0.0.1";

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
        kVersion);
}

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

}  // namespace

int main(const int argc, const char** argv)
{
    using namespace bazarish::admin;

    if (argc == 2 && std::strcmp(argv[1], "--version") == 0) {
        std::printf("bazarish-admin-panel %s\n", kVersion);
        return 0;
    }

    std::string configPath;
    for (int i = 1; i < argc;) {
        const std::string flag = argv[i];
        if (flag == "--config" && i + 1 < argc) {
            configPath = argv[i + 1];
            i += 2;
        } else {
            printUsage();
            return 2;
        }
    }
    if (configPath.empty()) {
        printUsage();
        return 2;
    }

    Config config;
    try {
        config = Config::fromFile(configPath);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "config: %s\n", error.what());
        return 2;
    }
    if (config.stateDir.empty() || config.assetsDir.empty()) {
        std::fprintf(stderr, "config: \"state\" and \"assets\" are required\n");
        return 2;
    }

    fs::create_directories(config.stateDir);
    const bazarish::Identity identity = loadOrCreateIdentity(config.stateDir);
    const std::string host = config.listenHost;
    const int port = config.listenPort;

    HttpApiOptions options;
    options.version = kVersion;
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

    std::printf("bazarish-admin-panel %s\n", kVersion);
    std::printf("panel operator fingerprint: %s\n", identity.fingerprint().c_str());
    std::printf("put this fingerprint in each service's \"operators\" list\n");
    std::printf("panel socket pin: %s\n", credential.pin.c_str());
    std::printf("put this pin in each service's \"opsClients\" list\n");
    std::printf("listening on %s:%d\n", host.c_str(), port);
    if (unclaimed) {
        std::printf("no administrator configured yet: open http://%s:%d/setup and sign in -\n"
                    "the first key to sign there administers this panel\n",
            host.c_str(), port);
    }
    std::fflush(stdout);

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
