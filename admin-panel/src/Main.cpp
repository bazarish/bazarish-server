// Bazarish project (c) 2026
#include "Config.hpp"
#include "HttpApi.hpp"
#include "PanelSettings.hpp"

#include <bazarish/Restart.hpp>

#include <bazarish/Crypto.hpp>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
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
        "signs every service call with its own identity (kept in <state>); add the\n"
        "printed fingerprint to each service's --operator-fingerprint. Sign in by\n"
        "signing a challenge with your client (bazarish-client sign-login); only the\n"
        "admin identity named in the config may sign in, and no backend needs to be\n"
        "online to log in.\n",
        kVersion);
}

std::string readFileText(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open " + path.string());
    }
    return std::string(
        (std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
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

// Loads the panel's own signing identity from the state directory, generating it
// on first start. The panel signs every service call with it.
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

    Config config = Config::fromFile(configPath);
    if (config.stateDir.empty() || config.assetsDir.empty()) {
        std::fprintf(stderr, "config: \"state\" and \"assets\" are required\n");
        return 2;
    }

    fs::create_directories(config.stateDir);
    const bazarish::Identity identity = loadOrCreateIdentity(config.stateDir);
    // The address is the config's to state. A flag that could override it would
    // mean two answers to the same question, and the operator finding out which
    // one won by reading a unit file.
    const std::string host = config.listenHost;
    const int port = config.listenPort;

    HttpApiOptions options;
    options.version = kVersion;
    options.assetsDirectory = config.assetsDir;
    // The panel administers itself: what it reads at start it can also write
    // back, into the same file the operator wrote by hand.
    const bool unclaimed = config.admins.empty();
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
        api.emplace(settings, identity, options);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "panel not started: %s\n", error.what());
        return 2;
    }

    std::printf("bazarish-admin-panel %s\n", kVersion);
    std::printf("panel operator fingerprint: %s\n", identity.fingerprint().c_str());
    std::printf("add this fingerprint to each service's --operator-fingerprint\n");
    std::printf("listening on %s:%d\n", host.c_str(), port);
    if (unclaimed) {
        // A fresh install: no administrator yet, and the first key to sign in
        // becomes one. Said on the console because that is where whoever just
        // installed it is looking.
        std::printf("no administrator configured yet: open http://%s:%d/setup and sign in -\n"
                    "the first key to sign there administers this panel\n",
            host.c_str(), port);
    }
    std::fflush(stdout);

    // Stopping happens on the switch's own thread: a handler must not stop the
    // server it is still answering on.
    bazarish::RestartSwitch restart([&api]() { api->stop(); });
    *restartHook = [&restart]() { restart.request(); };

    if (!api->listen(host, port)) {
        if (restart.requested()) {
            return bazarish::kRestartExitCode;
        }
        std::fprintf(stderr, "failed to listen on %s:%d\n", host.c_str(), port);
        return 1;
    }
    return restart.requested() ? bazarish::kRestartExitCode : 0;
}
