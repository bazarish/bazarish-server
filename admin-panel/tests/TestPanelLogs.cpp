// Bazarish project (c) 2026
#include "HttpApi.hpp"
#include "LogWindows.hpp"
#include "PanelSettings.hpp"
#include "TestUtil.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/HttpClient.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Percent.hpp>
#include <bazarish/Portal.hpp>
#include <bazarish/Tls.hpp>
#include <bazarish/WebSocketClient.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::admin;

namespace {

namespace http = bazarish::http;

constexpr const char* kChallengeField = "name=\"challenge\" value=\"";
constexpr std::chrono::milliseconds kFakeHold{50};
// A refused handshake keeps the dialing loop until this runs out.
constexpr std::chrono::seconds kRefusedDial{1};
constexpr int kOk = 200;
constexpr int kSeeOther = 303;
constexpr int kServerError = 500;

class FakeLog {
public:
    explicit FakeLog(std::string instance)
        : instance_(std::move(instance))
    {
    }

    void add(const std::string& text)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        lines_.push_back(text);
    }

    void restart(std::string instance, const std::string& text)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        instance_ = std::move(instance);
        lines_ = {text};
    }

    void fail(const bool failing)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        failing_ = failing;
    }

    bool asked(const std::uint64_t after) const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return std::find(asked_.begin(), asked_.end(), after) != asked_.end();
    }

    http::Response answer(const http::Request& request)
    {
        const std::uint64_t after = std::stoull(request.query("after"));
        nlohmann::json page;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            asked_.push_back(after);
            if (failing_) {
                return http::Response{kServerError, "application/json", {},
                    R"({"error":{"code":"REQUEST_FAILED","message":"the log is gone"}})"};
            }
            nlohmann::json lines = nlohmann::json::array();
            for (std::size_t at = after; at < lines_.size(); ++at) {
                lines.push_back(
                    {{"seq", at + 1}, {"t", 0}, {"level", "info"}, {"text", lines_[at]}});
            }
            page = {{"instance", instance_}, {"first", 1}, {"lines", lines}};
        }
        if (page.at("lines").empty()) {
            std::this_thread::sleep_for(kFakeHold);
        }
        return http::Response{kOk, "application/json", {}, page.dump()};
    }

private:
    mutable std::mutex mutex_;
    std::string instance_;
    std::vector<std::string> lines_;
    std::vector<std::uint64_t> asked_;
    bool failing_ = false;
};

class Window {
public:
    std::vector<nlohmann::json> frames() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return frames_;
    }

    bool closed() const { return closed_.load(); }

    void close()
    {
        if (socket) {
            socket->close();
        }
    }

    http::SocketPtr socket;
    std::string error;

    void heard(const std::vector<unsigned char>& message)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        frames_.push_back(nlohmann::json::parse(std::string(message.begin(), message.end())));
    }

    void ended() { closed_.store(true); }

    bool hasText(const std::string& text) const
    {
        for (const nlohmann::json& frame : frames()) {
            if (frame.value("type", "") != "lines") {
                continue;
            }
            for (const nlohmann::json& line : frame.at("lines")) {
                if (line.at("text") == text) {
                    return true;
                }
            }
        }
        return false;
    }

    std::optional<nlohmann::json> errorFrame() const
    {
        for (const nlohmann::json& frame : frames()) {
            if (frame.value("type", "") == "error") {
                return frame;
            }
        }
        return std::nullopt;
    }

private:
    mutable std::mutex mutex_;
    std::vector<nlohmann::json> frames_;
    std::atomic<bool> closed_{false};
};

std::string ownOrigin(const int port)
{
    return "http://127.0.0.1:" + std::to_string(port);
}

std::shared_ptr<Window> dial(const int port, const std::string& query, const std::string& cookie,
    const std::string& origin)
{
    const auto window = std::make_shared<Window>();
    http::SocketDial target;
    target.connectTimeout = kRefusedDial;
    target.host = "127.0.0.1";
    target.port = port;
    target.tls = false;
    target.path = "/api/logs?" + query;
    if (!cookie.empty()) {
        target.headers["Cookie"] = "adminsession=" + cookie;
    }
    target.headers["Origin"] = origin;
    const http::SocketDialResult dialed = http::openSocket(
        target,
        [window](const http::SocketPtr&, const std::vector<unsigned char>& message) {
            window->heard(message);
        },
        [window](const http::SocketPtr&) { window->ended(); });
    window->socket = dialed.socket;
    window->error = dialed.error;
    return window;
}

std::unique_ptr<http::Server> serving(const tls::Credential& credential)
{
    http::Server::Options options;
    options.certificate = credential.certificate.string();
    options.key = credential.key.string();
    options.port = 0;
    options.threads = static_cast<int>(kMaxLogWindows) + 1;
    return std::make_unique<http::Server>(options);
}

std::string signIn(const int port, const Identity& admin)
{
    http::ClientRequest page;
    page.method = "GET";
    page.target = "/login";
    const http::ClientResponse shown = http::request("127.0.0.1", port, page, {});
    const std::size_t start = shown.body.find(kChallengeField);
    CHECK(start != std::string::npos);
    const std::size_t from = start + std::char_traits<char>::length(kChallengeField);
    const std::string challenge = shown.body.substr(from, shown.body.find('"', from) - from);

    http::ClientRequest login;
    login.method = "POST";
    login.target = "/login";
    login.contentType = "application/x-www-form-urlencoded";
    login.body = "challenge=" + bazarish::percentEncode(challenge) + "&blob="
        + bazarish::percentEncode(service::signLoginBlob(
            admin, static_cast<std::int64_t>(std::time(nullptr)), challenge));
    const http::ClientResponse answered = http::request("127.0.0.1", port, login, {});
    CHECK(answered.status == kSeeOther);
    for (const auto& [name, value] : answered.headers) {
        if (name == "set-cookie") {
            const std::size_t equals = value.find('=');
            return value.substr(equals + 1, value.find(';') - equals - 1);
        }
    }
    CHECK(false);
    return {};
}

int pageStatus(const int port, const std::string& cookie)
{
    http::ClientRequest asked;
    asked.method = "GET";
    asked.target = "/logs?kind=server-core";
    if (!cookie.empty()) {
        asked.headers = {{"Cookie", "adminsession=" + cookie}};
    }
    return http::request("127.0.0.1", port, asked, {}).status;
}

}  // namespace

int main()
{
    bazarish::log::setLevel(bazarish::log::Level::eError);
    const std::filesystem::path root = testutil::freshDir("panel-logs-test");
    const tls::Credential services = tls::selfSigned(root / "services");
    const tls::Credential panelKeys = tls::selfSigned(root / "panel");

    FakeLog coreLog("first-run");
    coreLog.add("core one");
    coreLog.add("core two");
    const auto core = serving(services);
    core->get("/v1/messaging/logs", [&coreLog](const http::Request& request) {
        return coreLog.answer(request);
    });
    const int corePort = core->start();

    FakeLog edgeLog("edge-run");
    edgeLog.add("edge one");
    const auto edge = serving(services);
    edge->get("/logs",
        [&edgeLog](const http::Request& request) { return edgeLog.answer(request); });
    const int edgePort = edge->start();

    const auto at = [](const int port) { return "https://127.0.0.1:" + std::to_string(port); };
    const Identity admin = Identity::generate();
    const std::filesystem::path configPath = root / "admin-panel.json";
    { std::ofstream(configPath) << "{}\n"; }
    Config initial;
    initial.admins = {admin.fingerprint()};
    initial.consumer
        = service::LoginConsumer{"Bazarish admin panel", {"http://127.0.0.1"}, "Administrator"};
    initial.services = {ServiceEntry{"core", kServerCoreKind, at(corePort), services.pin},
        ServiceEntry{"edge", kGatewayKind, at(edgePort), services.pin}};
    const auto settings = std::make_shared<PanelSettings>(configPath, initial);

    HttpApiOptions options;
    options.version = "test";
    options.assetsDirectory = std::filesystem::path(BAZARISH_PANEL_WEB_DIR);
    const Identity panelIdentity = Identity::generate();
    {
        HttpApi api(settings, panelIdentity, panelKeys, options);
        const int port = api.bind("127.0.0.1", 0);
        CHECK(port > 0);
        std::thread serverThread([&api]() { api.wait(); });
        const std::string cookie = signIn(port, admin);
        const std::string coreQuery = "kind=server-core";

        CHECK(pageStatus(port, std::string()) == kSeeOther);
        CHECK(pageStatus(port, cookie) == kOk);

        CHECK(dial(port, coreQuery, std::string(), ownOrigin(port))->socket == nullptr);
        CHECK(dial(port, coreQuery, "not-a-session", ownOrigin(port))->socket == nullptr);
        CHECK(dial(port, coreQuery, cookie, "http://elsewhere.example")->socket == nullptr);
        CHECK(dial(port, coreQuery, cookie, std::string())->socket == nullptr);
        CHECK(dial(port, "service=nobody", cookie, ownOrigin(port))->socket == nullptr);
        CHECK(dial(port, coreQuery + "&after=2", cookie, ownOrigin(port))->socket == nullptr);

        const std::shared_ptr<Window> watching = dial(port, coreQuery, cookie, ownOrigin(port));
        CHECK(watching->socket != nullptr);
        CHECK(testutil::waitFor([&]() { return watching->hasText("core two"); }));
        const nlohmann::json opening = watching->frames().front();
        CHECK(opening.at("type") == "lines");
        CHECK(opening.at("instance") == "first-run");
        CHECK(opening.at("lines").size() == 2);
        CHECK(opening.at("lines")[0].at("seq") == 1);

        coreLog.add("core three");
        CHECK(testutil::waitFor([&]() { return watching->hasText("core three"); }));
        CHECK(coreLog.asked(2));
        CHECK(watching->frames().back().at("lines").size() == 1);
        CHECK(watching->frames().back().at("lines")[0].at("seq") == 3);

        coreLog.restart("second-run", "core after restart");
        CHECK(testutil::waitFor([&]() { return watching->hasText("core after restart"); }));
        CHECK(watching->frames().back().at("instance") == "second-run");
        CHECK(watching->frames().back().at("lines")[0].at("seq") == 1);

        const std::shared_ptr<Window> edgeWindow
            = dial(port, "service=edge", cookie, ownOrigin(port));
        CHECK(testutil::waitFor([&]() { return edgeWindow->hasText("edge one"); }));
        edgeWindow->close();

        const std::shared_ptr<Window> resumed = dial(
            port, coreQuery + "&after=1&instance=second-run", cookie, ownOrigin(port));
        coreLog.add("core resumed");
        CHECK(testutil::waitFor([&]() { return resumed->hasText("core resumed"); }));
        CHECK(!resumed->hasText("core after restart"));
        resumed->close();

        Config others = settings->get();
        others.admins = {Identity::generate().fingerprint()};
        settings->set(others);
        CHECK(testutil::waitFor([&]() { return watching->closed(); }));
        settings->set(initial);

        coreLog.fail(true);
        const std::shared_ptr<Window> failing = dial(port, coreQuery, cookie, ownOrigin(port));
        CHECK(testutil::waitFor([&]() { return failing->closed(); }));
        CHECK(failing->errorFrame().has_value());
        CHECK(failing->errorFrame()->at("message") == "the log is gone");
        coreLog.fail(false);

        CHECK(testutil::waitFor([&]() { return api.logWindowsOpen() == 0; }));
        std::vector<std::shared_ptr<Window>> many;
        for (std::size_t i = 0; i < kMaxLogWindows; ++i) {
            many.push_back(dial(port, coreQuery, cookie, ownOrigin(port)));
            CHECK(many.back()->socket != nullptr);
        }
        CHECK(testutil::waitFor([&]() { return api.logWindowsOpen() == kMaxLogWindows; }));
        const std::shared_ptr<Window> oneTooMany = dial(port, coreQuery, cookie, ownOrigin(port));
        CHECK(testutil::waitFor([&]() { return oneTooMany->closed(); }));
        CHECK(oneTooMany->errorFrame().has_value());
        CHECK(!oneTooMany->hasText("core one"));
        for (const std::shared_ptr<Window>& window : many) {
            CHECK(testutil::waitFor([&]() { return window->hasText("core resumed"); }));
            window->close();
        }
        CHECK(testutil::waitFor([&]() { return api.logWindowsOpen() == 0; }));

        api.stop();
        serverThread.join();
    }

    core->stop();
    edge->stop();
    std::filesystem::remove_all(root);
    std::printf("TestPanelLogs OK\n");
    return 0;
}
