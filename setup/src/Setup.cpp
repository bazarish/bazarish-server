// Bazarish project (c) 2026
#include "Setup.hpp"

#include <ServicePorts.hpp>
#include <Settings.hpp>
#include <StateIdentity.hpp>

#include <bazarish/Bytes.hpp>
#include <bazarish/ConfigFile.hpp>
#include <bazarish/Links.hpp>
#include <bazarish/PrivateFile.hpp>
#include <bazarish/Tls.hpp>

#include <arpa/inet.h>
#include <pwd.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <span>
#include <stdexcept>
#include <string_view>
#include <system_error>

namespace bazarish::setup {

namespace {

namespace fs = std::filesystem;

using ports::kLoopback;

constexpr int kJsonIndent = 2;
constexpr std::size_t kBasePathBytes = 16;
constexpr char kTokenSeparator = ':';
constexpr const char* kServiceUser = "bazarish";
constexpr const char* kSecureScheme = "https://";
constexpr std::string_view kWildcards[] = {"", "0.0.0.0", "::"};
constexpr std::string_view kLoopbacks[] = {"127.0.0.1", "::1", "localhost"};

constexpr const char* kListen = "listen";
constexpr const char* kOpsListen = "opsListen";
constexpr const char* kGatewayListen = "gatewayListen";
constexpr const char* kDirectListen = "directListen";
constexpr const char* kMessaging = "messaging";
constexpr const char* kServerService = "serverService";
constexpr const char* kOperators = "operators";
constexpr const char* kOpsClients = "opsClients";
constexpr const char* kServices = "services";
constexpr const char* kState = "state";

struct KindNames {
    Kind kind;
    const char* name;
    const char* unit;
};

constexpr std::array<KindNames, 5> kNames = {{
    {Kind::eServerCore, "server-core", "bazarish-server-core"},
    {Kind::eServerService, "server-service", "bazarish-server-service"},
    {Kind::eFacade, "facade", "bazarish-facade"},
    {Kind::eAdminPanel, "admin-panel", "bazarish-admin-panel"},
    {Kind::eGateway, "gateway", "bazarish-gateway"},
}};

const KindNames& namesOf(const Kind kind)
{
    for (const KindNames& names : kNames) {
        if (names.kind == kind) {
            return names;
        }
    }
    throw std::logic_error("a service kind without a name");
}

std::vector<std::string> socketKeysOf(const Kind kind)
{
    switch (kind) {
    case Kind::eServerCore:
        return {kListen, kOpsListen, kGatewayListen};
    case Kind::eServerService:
        return {kListen, kOpsListen};
    case Kind::eFacade:
        return {kOpsListen, kDirectListen};
    case Kind::eGateway:
        return {kOpsListen};
    case Kind::eAdminPanel:
        return {};
    }
    throw std::logic_error("a service kind without sockets");
}

bool hasFingerprint(const Kind kind)
{
    return kind == Kind::eServerService || kind == Kind::eAdminPanel;
}

bool oneOf(const std::string& host, const std::span<const std::string_view> names)
{
    return std::find(names.begin(), names.end(), host) != names.end();
}

std::string dialledHost(const std::string& host)
{
    return oneOf(host, kWildcards) ? kLoopback : host;
}

std::string urlOf(const Socket& socket)
{
    const std::string host
        = socket.host.find(':') == std::string::npos ? socket.host : "[" + socket.host + "]";
    return kSecureScheme + host + ":" + std::to_string(socket.port);
}

fs::path configOf(const Layout& layout, const Kind kind)
{
    return layout.configDir / (kindName(kind) + ".json");
}

nlohmann::json configJson(const Layout& layout, const Kind kind)
{
    return ConfigFile(configOf(layout, kind)).read();
}

nlohmann::json endpoint(const int port)
{
    return {{"host", kLoopback}, {"port", port}};
}

void own(const fs::path& path, const bool recursive)
{
    if (geteuid() != 0) {
        return;
    }
    const passwd* const user = getpwnam(kServiceUser);
    if (user == nullptr) {
        throw std::runtime_error(std::string("there is no user ") + kServiceUser);
    }
    const auto chownOne = [user](const fs::path& one) {
        if (lchown(one.c_str(), user->pw_uid, user->pw_gid) != 0) {
            throw std::system_error(errno, std::generic_category(), "cannot hand " + one.string() + " over");
        }
    };
    chownOne(path);
    if (recursive && fs::is_directory(path)) {
        for (const fs::directory_entry& entry : fs::recursive_directory_iterator(path)) {
            chownOne(entry.path());
        }
    }
}

nlohmann::json freshConfig(const Layout& layout, const Kind kind)
{
    const std::string state = (layout.stateDir / kindName(kind)).string();
    const nlohmann::json none = nlohmann::json::array();
    switch (kind) {
    case Kind::eServerCore:
        return {{kState, state}, {kListen, endpoint(ports::kCorePort)},
            {kOpsListen, endpoint(ports::kCoreOpsPort)},
            {kGatewayListen, endpoint(ports::kCoreGatewayPort)}, {kOperators, none},
            {kOpsClients, none}};
    case Kind::eServerService:
        return {{kState, state}, {kListen, endpoint(ports::kServerServicePort)},
            {kOpsListen, endpoint(ports::kServerServiceOpsPort)}, {kOperators, none},
            {kOpsClients, none}, {"portal", {{"assets", layout.portalAssets.string()}}}};
    case Kind::eFacade:
        return {{kState, state}, {kListen, endpoint(ports::kFacadePort)},
            {kDirectListen, endpoint(ports::kFacadeDirectPort)},
            {kOpsListen, endpoint(ports::kFacadeOpsPort)}, {kOperators, none},
            {kOpsClients, none}};
    case Kind::eAdminPanel:
        return {{kState, state}, {"assets", layout.panelAssets.string()},
            {kListen, endpoint(ports::kPanelPort)}, {kServices, none}};
    case Kind::eGateway:
        return {{kListen, endpoint(ports::kGatewayPort)},
            {"basePath", "/" + toHex(randomBytes(kBasePathBytes))}, {kState, state},
            {kOpsListen, endpoint(ports::kGatewayOpsPort)}, {kOperators, none},
            {kOpsClients, none}};
    }
    throw std::logic_error("a service kind without a config");
}

class Edits {
public:
    explicit Edits(const Layout& layout) : layout_(layout) {}

    void set(const Kind kind, const std::vector<std::string>& keys, const nlohmann::json& value)
    {
        const nlohmann::json current = configJson(layout_, kind);
        const nlohmann::json::json_pointer at(pointerOf(keys));
        if (current.contains(at) && current.at(at) == value) {
            return;
        }
        ConfigFile(configOf(layout_, kind)).set(keys, value);
        changed_.insert(kind);
    }

    void add(const Kind kind, const std::string& key, const std::string& entry)
    {
        const nlohmann::json current = configJson(layout_, kind).value(key, nlohmann::json::array());
        if (std::find(current.begin(), current.end(), entry) != current.end()) {
            return;
        }
        nlohmann::json grown = current;
        grown.push_back(entry);
        set(kind, {key}, grown);
    }

    Changed done() const
    {
        for (const Kind kind : changed_) {
            own(configOf(layout_, kind), false);
        }
        return changed_;
    }

private:
    static std::string pointerOf(const std::vector<std::string>& keys)
    {
        std::string pointer;
        for (const std::string& key : keys) {
            pointer += "/" + key;
        }
        return pointer;
    }

    const Layout& layout_;
    Changed changed_;
};

std::vector<Kind> installedKinds(const Layout& layout)
{
    std::vector<Kind> kinds;
    for (const Kind kind : kKinds) {
        if (installed(layout, kind)) {
            kinds.push_back(kind);
        }
    }
    return kinds;
}

std::string panelEntryName(const nlohmann::json& services, const Peer& peer, const Socket& ops)
{
    const std::string kind = kindName(peer.kind);
    if (peer.kind == Kind::eServerCore || peer.kind == Kind::eServerService) {
        return kind;
    }
    const auto taken = [&services](const std::string& name) {
        return std::any_of(services.begin(), services.end(),
            [&name](const nlohmann::json& service) { return service.at("name") == name; });
    };
    const std::string local = ops.host == kLoopback ? kind : kind + "-" + ops.host;
    return taken(local) ? local + "-" + std::to_string(ops.port) : local;
}

void listInPanel(const Layout& layout, Edits& edits, const Peer& peer)
{
    const Socket& ops = peer.sockets.at(kOpsListen);
    const std::string url = urlOf(ops);
    const std::string kind = kindName(peer.kind);
    const bool single = peer.kind == Kind::eServerCore || peer.kind == Kind::eServerService;
    nlohmann::json services = configJson(layout, Kind::eAdminPanel).value(kServices, nlohmann::json::array());
    for (nlohmann::json& service : services) {
        if (service.at("url") == url || (single && service.at("kind") == kind)) {
            service["kind"] = kind;
            service["url"] = url;
            service["pin"] = peer.pin;
            edits.set(Kind::eAdminPanel, {kServices}, services);
            return;
        }
    }
    services.push_back({{"name", panelEntryName(services, peer, ops)}, {"kind", kind}, {"url", url},
        {"pin", peer.pin}});
    edits.set(Kind::eAdminPanel, {kServices}, services);
}

nlohmann::json reachedAt(const Socket& socket, const std::string& pin)
{
    return {{"host", socket.host}, {"port", socket.port}, {"pin", pin}};
}

void apply(const Layout& layout, Edits& edits, const Peer& peer, const std::vector<Kind>& consumers)
{
    for (const Kind consumer : consumers) {
        if (consumer == peer.kind) {
            continue;
        }
        if (consumer == Kind::eAdminPanel && peer.kind != Kind::eAdminPanel) {
            listInPanel(layout, edits, peer);
            continue;
        }
        switch (peer.kind) {
        case Kind::eServerCore:
            if (consumer == Kind::eServerService) {
                edits.set(consumer, {kMessaging}, reachedAt(peer.sockets.at(kOpsListen), peer.pin));
            } else if (consumer == Kind::eFacade) {
                edits.set(consumer, {kMessaging}, reachedAt(peer.sockets.at(kListen), peer.pin));
            }
            break;
        case Kind::eServerService:
            if (consumer == Kind::eServerCore) {
                edits.set(consumer, {kServerService},
                    {{"url", urlOf(peer.sockets.at(kListen))}, {"pin", peer.pin}});
                edits.add(consumer, kOperators, peer.fingerprint);
                edits.add(consumer, kOpsClients, peer.pin);
            } else if (consumer == Kind::eFacade) {
                edits.set(consumer, {kServerService}, reachedAt(peer.sockets.at(kListen), peer.pin));
            }
            break;
        case Kind::eAdminPanel:
            edits.add(consumer, kOperators, peer.fingerprint);
            edits.add(consumer, kOpsClients, peer.pin);
            break;
        case Kind::eFacade:
        case Kind::eGateway:
            break;
        }
    }
}

Peer peerOf(const Layout& layout, const Kind kind, const bool dialledHere)
{
    const nlohmann::json config = configJson(layout, kind);
    const ConfigView view(config);
    Peer peer;
    peer.kind = kind;
    for (const std::string& key : socketKeysOf(kind)) {
        const std::optional<ConfigView::Endpoint> bound = view.endpoint(key);
        if (!bound.has_value()) {
            throw std::runtime_error(kindName(kind) + " has no \"" + key + "\"");
        }
        peer.sockets[key] = {dialledHere ? dialledHost(bound->host) : bound->host, bound->port};
    }
    const fs::path state = config.at(kState).get<std::string>();
    peer.pin = tls::selfSigned(state).pin;
    if (hasFingerprint(kind)) {
        peer.fingerprint = server::loadOrCreateIdentity(state).fingerprint();
    }
    return peer;
}

bool isAddress(const std::string& text)
{
    std::array<unsigned char, sizeof(in6_addr)> parsed{};
    return inet_pton(AF_INET, text.c_str(), parsed.data()) == 1
        || inet_pton(AF_INET6, text.c_str(), parsed.data()) == 1;
}

void relink(const Layout& layout, Edits& edits, const Socket& from, const Socket& to)
{
    const auto moved = [&from, &to](const nlohmann::json& link) {
        nlohmann::json out = link;
        out["host"] = to.host;
        out["port"] = to.port;
        return link.is_object() && link.value("host", std::string()) == from.host
                && link.value("port", 0) == from.port
            ? out
            : link;
    };
    for (const Kind kind : installedKinds(layout)) {
        const nlohmann::json config = configJson(layout, kind);
        for (const char* key : {kMessaging, kServerService}) {
            if (config.contains(key) && config.at(key).contains("host")) {
                edits.set(kind, {key}, moved(config.at(key)));
            }
        }
        if (kind == Kind::eServerCore && config.contains(kServerService)
            && config.at(kServerService).value("url", std::string()) == urlOf(from)) {
            edits.set(kind, {kServerService, "url"}, urlOf(to));
        }
        if (kind == Kind::eAdminPanel) {
            nlohmann::json services = config.value(kServices, nlohmann::json::array());
            for (nlohmann::json& service : services) {
                if (service.at("url") == urlOf(from)) {
                    service["url"] = urlOf(to);
                }
            }
            edits.set(kind, {kServices}, services);
        }
    }
}

}  // namespace

std::string kindName(const Kind kind)
{
    return namesOf(kind).name;
}

std::optional<Kind> kindNamed(const std::string& name)
{
    for (const KindNames& names : kNames) {
        if (name == names.name) {
            return names.kind;
        }
    }
    return std::nullopt;
}

std::string unitOf(const Kind kind)
{
    return namesOf(kind).unit;
}

bool installed(const Layout& layout, const Kind kind)
{
    return fs::exists(configOf(layout, kind));
}

std::vector<std::string> missing(const Layout& layout, const Kind kind)
{
    const nlohmann::json config = configJson(layout, kind);
    const auto linked = [&config](const char* key, const char* reach) {
        return config.contains(key) && !config.at(key).value(reach, std::string()).empty()
            && !config.at(key).value("pin", std::string()).empty();
    };
    std::vector<std::string> wanted;
    if ((kind == Kind::eServerService || kind == Kind::eFacade) && !linked(kMessaging, "host")) {
        wanted.push_back(kindName(Kind::eServerCore));
    }
    if (kind == Kind::eServerCore && !linked(kServerService, "url")) {
        wanted.push_back(kindName(Kind::eServerService));
    }
    if (kind == Kind::eFacade && !linked(kServerService, "host")) {
        wanted.push_back(kindName(Kind::eServerService));
    }
    return wanted;
}

Changed init(const Layout& layout, const Kind kind)
{
    if (installed(layout, kind)) {
        return {};
    }
    fs::create_directories(layout.configDir);
    const nlohmann::json config = freshConfig(layout, kind);
    const fs::path state = config.at(kState).get<std::string>();
    fs::create_directories(state);
    writePrivateFile(configOf(layout, kind), config.dump(kJsonIndent) + "\n");
    const Peer made = peerOf(layout, kind, true);
    own(state, true);

    Edits edits(layout);
    std::vector<Kind> others;
    for (const Kind other : installedKinds(layout)) {
        if (other != kind) {
            others.push_back(other);
        }
    }
    apply(layout, edits, made, others);
    for (const Kind other : others) {
        apply(layout, edits, peerOf(layout, other, true), {kind});
    }
    Changed changed = edits.done();
    changed.insert(kind);
    own(configOf(layout, kind), false);
    return changed;
}

Peer localPeer(const Layout& layout, const Kind kind)
{
    return peerOf(layout, kind, true);
}

std::string token(const Layout& layout, const Kind kind)
{
    const Peer peer = peerOf(layout, kind, false);
    nlohmann::json sockets = nlohmann::json::object();
    for (const auto& [key, socket] : peer.sockets) {
        if (oneOf(socket.host, kWildcards) || oneOf(socket.host, kLoopbacks)) {
            throw std::invalid_argument("the " + kindName(kind) + " listens on \"" + socket.host
                + "\" for \"" + key + "\": bazarish-setup listen " + kindName(kind)
                + " <address another host reaches>");
        }
        sockets[key] = {{"host", socket.host}, {"port", socket.port}};
    }
    const nlohmann::json body = {{"sockets", sockets}, {"pin", peer.pin}, {"fingerprint", peer.fingerprint}};
    const std::string text = body.dump();
    return kindName(kind) + kTokenSeparator + toBase64Url(Bytes(text.begin(), text.end()));
}

Peer peerFromToken(const std::string& text)
{
    const std::size_t split = text.find(kTokenSeparator);
    const std::optional<Kind> kind
        = split == std::string::npos ? std::nullopt : kindNamed(text.substr(0, split));
    if (!kind.has_value()) {
        throw std::invalid_argument("a token starts with the kind of service it names");
    }
    const Bytes raw = fromBase64Url(text.substr(split + 1));
    const nlohmann::json body = nlohmann::json::parse(raw.begin(), raw.end());
    Peer peer;
    peer.kind = *kind;
    peer.pin = body.at("pin").get<std::string>();
    peer.fingerprint = body.at("fingerprint").get<std::string>();
    if (peer.pin.empty() || (hasFingerprint(peer.kind) && peer.fingerprint.empty())) {
        throw std::invalid_argument("this " + kindName(peer.kind) + " token names no key");
    }
    for (const std::string& key : socketKeysOf(peer.kind)) {
        const nlohmann::json& socket = body.at("sockets").at(key);
        peer.sockets[key] = {socket.at("host").get<std::string>(), socket.at("port").get<int>()};
        if (!isAddress(peer.sockets[key].host) || peer.sockets[key].port < kMinPort
            || peer.sockets[key].port > kMaxPort) {
            throw std::invalid_argument("this token names no address for \"" + key + "\"");
        }
    }
    return peer;
}

Changed join(const Layout& layout, const Peer& peer)
{
    if (installed(layout, peer.kind)) {
        throw std::invalid_argument("a " + kindName(peer.kind) + " is installed here already");
    }
    const std::vector<Kind> here = installedKinds(layout);
    if (here.empty()) {
        throw std::invalid_argument("no Bazarish service is installed here");
    }
    Edits edits(layout);
    apply(layout, edits, peer, here);
    return edits.done();
}

Changed listenOn(const Layout& layout, const Kind kind, const std::string& address)
{
    if (!isAddress(address) || oneOf(address, kWildcards)) {
        throw std::invalid_argument("\"" + address + "\" is not one address of this host");
    }
    if (socketKeysOf(kind).empty()) {
        throw std::invalid_argument("the " + kindName(kind) + " is reached by nothing on another host");
    }
    const Peer before = peerOf(layout, kind, true);
    Edits edits(layout);
    for (const std::string& key : socketKeysOf(kind)) {
        edits.set(kind, {key, "host"}, address);
    }
    for (const auto& [key, socket] : before.sockets) {
        relink(layout, edits, socket, {address, socket.port});
    }
    return edits.done();
}

Changed setGatewayAddress(const Layout& layout, const std::string& address)
{
    if (address.empty()) {
        throw std::invalid_argument("a gateway's public address is http(s)://host[:port]");
    }
    Edits edits(layout);
    edits.set(Kind::eGateway, {"publicAddress"}, gateway::publicAddressFrom(address));
    return edits.done();
}

std::string gatewayLink(const Layout& layout)
{
    const nlohmann::json config = configJson(layout, Kind::eGateway);
    const std::string address = config.value("publicAddress", std::string());
    if (address.empty()) {
        throw std::invalid_argument(
            "the gateway has no public address yet: bazarish-setup gateway-link https://<its name>");
    }
    const std::string fingerprint
        = server::loadOrCreateIdentity(config.at(kState).get<std::string>()).fingerprint();
    return bazarish::gatewayLink(address + config.at("basePath").get<std::string>(), fingerprint);
}

nlohmann::json status(const Layout& layout)
{
    nlohmann::json services = nlohmann::json::array();
    for (const Kind kind : installedKinds(layout)) {
        const Peer peer = peerOf(layout, kind, false);
        const nlohmann::json config = configJson(layout, kind);
        nlohmann::json sockets = nlohmann::json::object();
        for (const auto& [key, socket] : peer.sockets) {
            sockets[key] = {{"host", socket.host}, {"port", socket.port}};
        }
        nlohmann::json shown = {{"kind", kindName(kind)}, {"unit", unitOf(kind)},
            {"missing", missing(layout, kind)}, {"sockets", sockets}, {"pin", peer.pin}};
        if (!peer.fingerprint.empty()) {
            shown["fingerprint"] = peer.fingerprint;
        }
        for (const char* key : {kMessaging, kServerService}) {
            if (config.contains(key)) {
                shown[key] = config.at(key);
            }
        }
        if (kind == Kind::eAdminPanel) {
            shown[kServices] = config.value(kServices, nlohmann::json::array());
        }
        if (kind == Kind::eGateway && !config.value("publicAddress", std::string()).empty()) {
            shown["link"] = gatewayLink(layout);
        }
        services.push_back(shown);
    }
    return services;
}

}  // namespace bazarish::setup
