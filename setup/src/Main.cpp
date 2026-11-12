// Bazarish project (c) 2026
#include "ServerSetup.hpp"

#include <cstdio>

namespace {

constexpr const char* kConfigDir = "/etc/bazarish";
constexpr const char* kStateDir = "/var/lib/bazarish";
constexpr const char* kPanelAssets = "/usr/share/bazarish-server/admin-panel";
constexpr const char* kPortalAssets = "/usr/share/bazarish-server/portal";

}  // namespace

int main(const int argc, const char**)
{
    if (argc != 1) {
        std::printf(
            "Usage: bazarish-setup\n"
            "\n"
            "Writes the configs of server-core, the service node, the facade and the\n"
            "admin panel into %s, makes the keys each of them presents under %s,\n"
            "and opens the gateway's operator socket to the panel. Once any of the\n"
            "four configs is there it changes nothing.\n",
            kConfigDir, kStateDir);
        return 2;
    }
    if (!bazarish::setup::setUpServer(
            {kConfigDir, kStateDir, kPanelAssets, kPortalAssets})) {
        return 0;
    }
    std::printf(
        "The Bazarish server is set up. To finish:\n"
        "\n"
        "1. From your computer, open a tunnel to the admin panel:\n"
        "       ssh -L %d:127.0.0.1:%d <user>@<this host>\n"
        "   then http://127.0.0.1:%d/setup in a browser. The first key to sign the\n"
        "   challenge there administers the panel.\n"
        "2. Give users the descriptor shown under Settings, Addresses.\n"
        "3. For the browser portal and the private reseed, give the portal its public\n"
        "   HTTPS address under Settings, Portal and put a TLS front before its socket.\n",
        bazarish::setup::kPanelPort, bazarish::setup::kPanelPort, bazarish::setup::kPanelPort);
    return 0;
}
