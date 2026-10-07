// Bazarish project (c) 2026
#include "AdminAuth.hpp"
#include "PanelSettings.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Portal.hpp>

#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <string>

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

namespace fs = std::filesystem;

constexpr std::int64_t kNow = 1'700'000'000;

fs::path writeConfig(const std::string& text)
{
    const fs::path path
        = fs::temp_directory_path() / ("bazarish-panel-" + toHex(randomBytes(8)) + ".json");
    std::ofstream out(path);
    out << text;
    return path;
}

nlohmann::json read(const fs::path& path)
{
    std::ifstream in(path);
    return nlohmann::json::parse(in);
}

}  // namespace

int main()
{
    {
        const fs::path path = writeConfig(R"({
  "state": "/var/lib/bazarish/admin-panel",
  "assets": "/opt/bazarish/web",
  "listen": {"host": "0.0.0.0", "port": 8460}
})");
        Config config = Config::fromFile(path.string());
        CHECK(config.admins.empty());
        const auto settings = std::make_shared<PanelSettings>(path, std::move(config));
        CHECK(settings->unclaimed());

        const Identity owner = Identity::generate();
        CHECK(settings->claim(owner.fingerprint()));
        CHECK(!settings->unclaimed());
        CHECK(!settings->claim(Identity::generate().fingerprint()));
        CHECK(settings->get().admins.size() == 1);

        const nlohmann::json written = read(path);
        CHECK(written.at("admin").at(0).get<std::string>() == owner.fingerprint());
        CHECK(written.at("state").get<std::string>() == "/var/lib/bazarish/admin-panel");
        CHECK(written.at("listen").at("port").get<int>() == 8460);

        AdminAuth panelAuth(settings);
        const std::string challenge = panelAuth.issueChallenge(kNow);
        const auth::Headers headers = auth::signRequest(owner, kNow, service::kLoginMethod,
            service::kLoginPath, Bytes(challenge.begin(), challenge.end()));
        const nlohmann::json blob = {{"k", headers.at(auth::kHeaderKeys)},
            {"n", headers.at(auth::kHeaderNonce)},
            {"t", headers.at(auth::kHeaderTimestamp)},
            {"c", headers.at(auth::kHeaderSignatureClassical)},
            {"p", headers.at(auth::kHeaderSignaturePq)}};
        const std::string text = blob.dump();
        CHECK(panelAuth.login(challenge, toBase64(Bytes(text.begin(), text.end())), kNow)
            == owner.fingerprint());
        fs::remove(path);
    }

    {
        const fs::path path = writeConfig(R"({
  "admin": ["kg3xjmqsuwzq5xakkyk6cqiwpxu63xqcprzhcy4wkeegj7ivhtxq"],
  "state": "/var/lib/bazarish/admin-panel",
  "assets": "/opt/bazarish/web",
  "listen": {"host": "127.0.0.1", "port": 8460}
})");
        Config config = Config::fromFile(path.string());
        const auto settings = std::make_shared<PanelSettings>(path, config);

        Config wanted = config;
        wanted.consumer.name = "Bazarish alpha panel";
        wanted.consumer.place = "https://panel.example";
        wanted.consumer.role = "Administrator";
        wanted.listenPort = 9460;
        wanted.fleets = {Fleet{"alpha", {ServiceEntry{"core", "server-core",
                                            "http://127.0.0.1:8420", {}}}}};
        settings->set(wanted);

        const nlohmann::json written = read(path);
        CHECK(written.at("consumer").at("name").get<std::string>() == "Bazarish alpha panel");
        CHECK(written.at("consumer").at("place").get<std::string>() == "https://panel.example");
        CHECK(written.at("listen").at("port").get<int>() == 9460);
        CHECK(written.at("listen").at("host").get<std::string>() == "127.0.0.1");
        CHECK(written.at("fleets").at(0).at("services").at(0).at("kind").get<std::string>()
            == "server-core");
        CHECK(written.at("assets").get<std::string>() == "/opt/bazarish/web");

        const Config again = Config::fromFile(path.string());
        CHECK(again.listenPort == 9460);
        CHECK(again.fleets.size() == 1);
        CHECK(again.fleets.front().services.front().url == "http://127.0.0.1:8420");
        fs::remove(path);
    }

    {
        Config config;
        config.admins = {"kg3xjmqsuwzq5xakkyk6cqiwpxu63xqcprzhcy4wkeegj7ivhtxq"};
        PanelSettings settings{fs::path(), config};
        Config wanted = config;
        wanted.listenPort = 9999;
        bool refused = false;
        try {
            settings.set(wanted);
        } catch (const std::exception&) {
            refused = true;
        }
        CHECK(refused);
        CHECK(settings.get().listenPort == config.listenPort);
    }

    std::printf("TestPanelSettings: all checks passed\n");
    return 0;
}
