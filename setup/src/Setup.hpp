// Bazarish project (c) 2026
#pragma once

#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace bazarish::setup {

enum class Kind { eServerCore, eServerService, eFacade, eAdminPanel, eGateway };

inline constexpr Kind kKinds[]
    = {Kind::eServerCore, Kind::eServerService, Kind::eFacade, Kind::eAdminPanel, Kind::eGateway};

std::string kindName(Kind kind);
std::optional<Kind> kindNamed(const std::string& name);
std::string unitOf(Kind kind);

struct Layout {
    std::filesystem::path configDir;
    std::filesystem::path stateDir;
    std::filesystem::path panelAssets;
    std::filesystem::path portalAssets;
};

struct Socket {
    std::string host;
    int port = 0;

    bool operator==(const Socket&) const = default;
};

// What another service needs to reach and trust one service; a token carries one.
struct Peer {
    Kind kind = Kind::eServerCore;
    std::map<std::string, Socket> sockets;
    std::string pin;
    std::string fingerprint;
};

using Changed = std::set<Kind>;

bool installed(const Layout& layout, Kind kind);
// Empty when the service has every link it needs to start.
std::vector<std::string> missing(const Layout& layout, Kind kind);

// Writes the service's config and keys once, and links it with the services already here.
Changed init(const Layout& layout, Kind kind);

Peer localPeer(const Layout& layout, Kind kind);
std::string token(const Layout& layout, Kind kind);
Peer peerFromToken(const std::string& text);
Changed join(const Layout& layout, const Peer& peer);

// Moves the sockets other hosts dial onto this address, and the links of the services here with them.
Changed listenOn(const Layout& layout, Kind kind, const std::string& address);

Changed setGatewayAddress(const Layout& layout, const std::string& address);
std::string gatewayLink(const Layout& layout);

nlohmann::json status(const Layout& layout);

}  // namespace bazarish::setup
