// Bazarish project (c) 2026
#include "Setup.hpp"

#include <ServicePorts.hpp>

#include <sys/wait.h>

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;
namespace setup = bazarish::setup;

constexpr const char* kConfigDir = "/etc/bazarish";
constexpr const char* kStateDir = "/var/lib/bazarish";
constexpr const char* kPanelAssets = "/usr/share/bazarish-admin-panel/web";
constexpr const char* kPortalAssets = "/usr/share/bazarish-server-service/portal";
constexpr const char* kSystemdRunning = "/run/systemd/system";
constexpr int kNotReady = 1;
constexpr int kFailed = 1;
constexpr int kUsage = 2;
constexpr int kJsonIndent = 2;

void printUsage()
{
    std::printf(
        "Usage: bazarish-setup init <service>\n"
        "       bazarish-setup ready <service>\n"
        "       bazarish-setup waiting\n"
        "       bazarish-setup status [--json]\n"
        "       bazarish-setup token <service>\n"
        "       bazarish-setup join <token>\n"
        "       bazarish-setup listen <service> <address>\n"
        "       bazarish-setup gateway-link [<public address>]\n"
        "\n"
        "<service> is server-core, server-service, facade, admin-panel or gateway.\n"
        "\n"
        "init          writes the service's config and keys under %s and %s,\n"
        "              once, and links it with the services already on this host.\n"
        "ready         exits 0 when the service has every link it needs to start.\n"
        "waiting       says what each service here still waits for, and how to give it.\n"
        "status        what is installed here: its sockets, keys and links.\n"
        "token         one line with what another host needs of this service: where\n"
        "              to reach it and the key it presents.\n"
        "join          links the services on this host with the one a token names.\n"
        "listen        moves the sockets other hosts reach onto this address.\n"
        "gateway-link  prints the link clients take for this gateway, after setting\n"
        "              its public address when one is given.\n"
        "\n"
        "A changed service whose unit is enabled is restarted.\n",
        kConfigDir, kStateDir);
}

setup::Kind kindArgument(const std::string& name)
{
    const std::optional<setup::Kind> kind = setup::kindNamed(name);
    if (!kind.has_value()) {
        throw std::invalid_argument("\"" + name
            + "\" is none of server-core, server-service, facade, admin-panel, gateway");
    }
    return *kind;
}

int run(const std::string& command)
{
    const int status = std::system(command.c_str());
    if (status == -1 || !WIFEXITED(status)) {
        throw std::runtime_error("cannot run " + command);
    }
    return WEXITSTATUS(status);
}

void restart(const setup::Changed& changed)
{
    for (const setup::Kind kind : changed) {
        const std::string unit = setup::unitOf(kind);
        if (!fs::exists(kSystemdRunning)) {
            std::printf("changed: %s\n", unit.c_str());
            continue;
        }
        if (run("systemctl is-enabled --quiet " + unit) != 0) {
            continue;
        }
        if (run("systemctl restart " + unit) != 0) {
            throw std::runtime_error(unit + " did not restart: journalctl -u " + unit);
        }
        std::printf("restarted: %s\n", unit.c_str());
    }
}

void tellMissing(const setup::Layout& layout, const setup::Kind kind)
{
    for (const std::string& wanted : setup::missing(layout, kind)) {
        std::printf("The %s starts once it is linked with a %s. On that host:\n"
                    "    bazarish-setup token %s\n"
                    "and here:\n"
                    "    bazarish-setup join <that token>\n",
            setup::kindName(kind).c_str(), wanted.c_str(), wanted.c_str());
    }
}

void tellWaiting(const setup::Layout& layout)
{
    for (const setup::Kind kind : setup::kKinds) {
        if (setup::installed(layout, kind)) {
            tellMissing(layout, kind);
        }
    }
}

void tellInstalled(const setup::Kind kind)
{
    if (kind == setup::Kind::eAdminPanel) {
        std::printf("The admin panel listens on 127.0.0.1:%d. From your computer:\n"
                    "    ssh -L %d:127.0.0.1:%d <user>@<this host>\n"
                    "then open http://127.0.0.1:%d/setup: the first key to sign there\n"
                    "administers the panel.\n",
            bazarish::ports::kPanelPort, bazarish::ports::kPanelPort, bazarish::ports::kPanelPort,
            bazarish::ports::kPanelPort);
    }
    if (kind == setup::Kind::eGateway) {
        std::printf("The gateway listens on 127.0.0.1:%d. Put a TLS front before it\n"
                    "(/usr/share/doc/bazarish-gateway/README.md), then:\n"
                    "    bazarish-setup gateway-link https://<the front's name>\n",
            bazarish::ports::kGatewayPort);
    }
}

void printStatus(const nlohmann::json& services)
{
    for (const nlohmann::json& service : services) {
        const bool ready = service.at("missing").empty();
        std::printf("%s (%s): %s\n", service.at("kind").get<std::string>().c_str(),
            service.at("unit").get<std::string>().c_str(), ready ? "ready" : "not linked yet");
        for (const auto& [key, socket] : service.at("sockets").items()) {
            std::printf("  %-14s %s:%d\n", key.c_str(), socket.at("host").get<std::string>().c_str(),
                socket.at("port").get<int>());
        }
        std::printf("  %-14s %s\n", "pin", service.at("pin").get<std::string>().c_str());
        if (service.contains("fingerprint")) {
            std::printf("  %-14s %s\n", "fingerprint",
                service.at("fingerprint").get<std::string>().c_str());
        }
        for (const nlohmann::json& wanted : service.at("missing")) {
            std::printf("  %-14s %s\n", "needs", wanted.get<std::string>().c_str());
        }
        if (service.contains("services")) {
            for (const nlohmann::json& listed : service.at("services")) {
                std::printf("  %-14s %s %s\n", "manages",
                    listed.at("name").get<std::string>().c_str(),
                    listed.at("url").get<std::string>().c_str());
            }
        }
        if (service.contains("link")) {
            std::printf("  %-14s %s\n", "link", service.at("link").get<std::string>().c_str());
        }
    }
}

int dispatch(const std::vector<std::string>& args)
{
    const setup::Layout layout{kConfigDir, kStateDir, kPanelAssets, kPortalAssets};
    const std::string command = args.empty() ? std::string() : args.at(0);
    if (command == "init" && args.size() == 2) {
        const setup::Kind kind = kindArgument(args.at(1));
        const setup::Changed changed = setup::init(layout, kind);
        if (!changed.empty()) {
            tellInstalled(kind);
        }
        restart(changed);
        return 0;
    }
    if (command == "ready" && args.size() == 2) {
        const setup::Kind kind = kindArgument(args.at(1));
        return setup::installed(layout, kind) && setup::missing(layout, kind).empty()
            ? 0
            : kNotReady;
    }
    if (command == "status" && (args.size() == 1 || (args.size() == 2 && args.at(1) == "--json"))) {
        const nlohmann::json services = setup::status(layout);
        if (args.size() == 2) {
            std::printf("%s\n", services.dump(kJsonIndent).c_str());
        } else {
            printStatus(services);
        }
        return 0;
    }
    if (command == "token" && args.size() == 2) {
        std::printf("%s\n", setup::token(layout, kindArgument(args.at(1))).c_str());
        return 0;
    }
    if (command == "join" && args.size() == 2) {
        restart(setup::join(layout, setup::peerFromToken(args.at(1))));
        tellWaiting(layout);
        return 0;
    }
    if (command == "waiting" && args.size() == 1) {
        tellWaiting(layout);
        return 0;
    }
    if (command == "listen" && args.size() == 3) {
        restart(setup::listenOn(layout, kindArgument(args.at(1)), args.at(2)));
        return 0;
    }
    if (command == "gateway-link" && args.size() <= 2) {
        if (args.size() == 2) {
            restart(setup::setGatewayAddress(layout, args.at(1)));
        }
        std::printf("%s\n", setup::gatewayLink(layout).c_str());
        return 0;
    }
    printUsage();
    return kUsage;
}

}  // namespace

int main(const int argc, const char** argv)
{
    try {
        return dispatch(std::vector<std::string>(argv + 1, argv + argc));
    } catch (const std::exception& error) {
        std::fprintf(stderr, "bazarish-setup: %s\n", error.what());
        return kFailed;
    }
}
