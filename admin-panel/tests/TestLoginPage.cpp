// Bazarish project (c) 2026
#include "HttpApi.hpp"
#include "PanelSettings.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/HttpClient.hpp>
#include <bazarish/Log.hpp>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <thread>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

using namespace bazarish;
using namespace bazarish::admin;

namespace {

namespace http = bazarish::http;

// A form body: the challenge is base64 and carries characters a form encodes.
std::string formEncoded(const std::string& text)
{
    std::string out;
    for (const unsigned char c : text) {
        if (c == '+') {
            out += "%2B";
        } else if (c == '/') {
            out += "%2F";
        } else if (c == '=') {
            out += "%3D";
        } else {
            out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

}  // namespace

int main()
{
    bazarish::log::setLevel(bazarish::log::Level::eError);
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-loginpage-test";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);
    const std::filesystem::path configPath = root / "admin-panel.json";
    { std::ofstream(configPath) << "{}\n"; }

    Config initial;
    initial.admins = {"jmqwewpdvbdns4x7ojmdxtznznkit6dhdt3ftaozjmkjb2cnmexq"};
    initial.consumer
        = service::LoginConsumer{"Bazarish admin panel", {"http://127.0.0.1"}, "Administrator"};
    const auto settings = std::make_shared<PanelSettings>(configPath, initial);
    const Identity identity = Identity::generate();

    HttpApiOptions options;
    options.version = "test";
    options.assetsDirectory = std::filesystem::path(BAZARISH_PANEL_WEB_DIR);
    HttpApi api(settings, identity, options);
    const int port = api.bind("127.0.0.1", 0);
    CHECK(port > 0);
    std::thread serverThread([&api]() { api.wait(); });

    const std::string payload = R"("<script>alert(document.domain)</script>)";
    const std::string challenge = toBase64(Bytes(payload.begin(), payload.end()));
    http::ClientRequest request;
    request.method = "POST";
    request.target = "/login";
    request.contentType = "application/x-www-form-urlencoded";
    request.body = "challenge=" + formEncoded(challenge) + "&blob=x";
    const http::ClientResponse refused = http::request("127.0.0.1", port, request, {});

    CHECK(refused.status == 401);
    CHECK(refused.body.find("is-error") != std::string::npos);
    CHECK(refused.body.find("<script>alert") == std::string::npos);
    CHECK(refused.body.find("&lt;script&gt;") != std::string::npos);

    api.stop();
    serverThread.join();
    std::filesystem::remove_all(root);
    std::printf("TestLoginPage OK\n");
    return 0;
}
