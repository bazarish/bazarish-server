// Bazarish project (c) 2026
#include "TlsPipe.hpp"
#include "TestUtil.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Tls.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <sys/socket.h>

#include <atomic>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace fs = std::filesystem;
using boost::asio::ip::tcp;
using bazarish::server::TlsPipe;

namespace {

constexpr std::chrono::seconds kDeadline{5};
constexpr std::chrono::seconds kExpiry{1};
constexpr std::size_t kLineBytes = 64;
constexpr int kRandomNameBytes = 8;

class Listener {
public:
    explicit Listener(const bazarish::tls::Credential& own)
        : acceptor_(io_, tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0))
        , own_(own)
    {
    }

    int port() const { return acceptor_.local_endpoint().port(); }

    std::future<std::unique_ptr<TlsPipe>> next()
    {
        return std::async(std::launch::async, [this]() {
            tcp::socket socket(io_);
            acceptor_.accept(socket);
            return TlsPipe::serve(AF_INET, socket.release(), own_, kDeadline);
        });
    }

private:
    boost::asio::io_context io_;
    tcp::acceptor acceptor_;
    const bazarish::tls::Credential own_;
};

std::string readAll(TlsPipe& pipe, const std::size_t want)
{
    std::string out;
    std::array<unsigned char, kLineBytes> buffer{};
    while (out.size() < want) {
        const std::size_t got = pipe.readSome(buffer);
        if (got == 0) {
            break;
        }
        out.append(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(got));
    }
    return out;
}

}  // namespace

int main()
{
    const fs::path root = fs::temp_directory_path()
        / ("bazarish-tls-pipe-" + bazarish::toHex(bazarish::randomBytes(kRandomNameBytes)));
    fs::create_directories(root / "a");
    fs::create_directories(root / "b");
    const bazarish::tls::Credential gateway = bazarish::tls::selfSigned(root / "a");
    const bazarish::tls::Credential server = bazarish::tls::selfSigned(root / "b");
    Listener listener(server);

    {
        std::future<std::unique_ptr<TlsPipe>> accepted = listener.next();
        const std::unique_ptr<TlsPipe> client
            = TlsPipe::dial("127.0.0.1", listener.port(), server.pin, kDeadline, gateway);
        const std::unique_ptr<TlsPipe> served = accepted.get();
        CHECK(served->peerPin() == gateway.pin);
        CHECK(client->peerPin() == server.pin);

        const std::string sent = "{\"watch\": true}\nafter";
        client->writeAll(bazarish::viewOf(sent));
        CHECK(served->readLine(kLineBytes) == "{\"watch\": true}");
        CHECK(readAll(*served, std::string("after").size()) == "after");

        const std::string answer = "back";
        served->writeAll(bazarish::viewOf(answer));
        CHECK(readAll(*client, answer.size()) == answer);

        std::mutex mutex;
        std::condition_variable told;
        bool ended = false;
        // Notified under the lock: the waiter destroys the condition as soon as it wakes.
        served->whenEnded([&]() {
            const std::lock_guard<std::mutex> lock(mutex);
            ended = true;
            told.notify_all();
        });
        client->close();
        std::unique_lock<std::mutex> lock(mutex);
        CHECK(told.wait_for(lock, kDeadline, [&]() { return ended; }));
    }

    {
        std::future<std::unique_ptr<TlsPipe>> accepted = listener.next();
        const std::unique_ptr<TlsPipe> client
            = TlsPipe::dial("127.0.0.1", listener.port(), server.pin, kDeadline, gateway);
        const std::unique_ptr<TlsPipe> served = accepted.get();
        const auto started = std::chrono::steady_clock::now();
        served->closeAfter(kExpiry);
        std::array<unsigned char, 1> byte{};
        CHECK(client->readSome(byte) == 0);
        CHECK(std::chrono::steady_clock::now() - started >= kExpiry);
    }

    {
        std::future<std::unique_ptr<TlsPipe>> accepted = listener.next();
        bool refused = false;
        try {
            const std::unique_ptr<TlsPipe> client
                = TlsPipe::dial("127.0.0.1", listener.port(), gateway.pin, kDeadline, gateway);
        } catch (const std::exception&) {
            refused = true;
        }
        CHECK(refused);
        accepted.wait();
    }

    {
        std::future<std::unique_ptr<TlsPipe>> accepted = listener.next();
        const std::unique_ptr<TlsPipe> anonymous
            = TlsPipe::dial("127.0.0.1", listener.port(), server.pin, kDeadline);
        bool refused = false;
        try {
            const std::unique_ptr<TlsPipe> served = accepted.get();
            std::array<unsigned char, 1> byte{};
            refused = anonymous->readSome(byte) == 0;
        } catch (const std::exception&) {
            refused = true;
        }
        CHECK(refused);
    }

    fs::remove_all(root);
    std::printf("TestTlsPipe: all checks passed\n");
    return 0;
}
