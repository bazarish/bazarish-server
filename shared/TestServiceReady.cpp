// Bazarish project (c) 2026
#include "ServiceReady.hpp"
#include "TestUtil.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>

using namespace bazarish;

namespace {

constexpr std::size_t kNameBytes = 8;
constexpr std::size_t kDatagramBytes = 64;
constexpr const char* kReady = "READY=1";

int boundAt(const std::string& name, const bool abstract)
{
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path + (abstract ? 1 : 0), name.data(), name.size());
    const int fd = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    const socklen_t length = static_cast<socklen_t>(
        offsetof(sockaddr_un, sun_path) + name.size() + (abstract ? 1 : 0));
    CHECK(::bind(fd, reinterpret_cast<const sockaddr*>(&address), length) == 0);
    return fd;
}

std::string received(const int fd)
{
    std::array<char, kDatagramBytes> buffer{};
    const ssize_t got = ::recv(fd, buffer.data(), buffer.size(), MSG_DONTWAIT);
    CHECK(got > 0);
    return std::string(buffer.data(), static_cast<std::size_t>(got));
}

}  // namespace

int main()
{
    const std::filesystem::path root = testutil::freshDir("service-ready");
    std::filesystem::create_directories(root);
    std::filesystem::current_path(root);

    CHECK(::unsetenv("NOTIFY_SOCKET") == 0);
    announceReady();

    const std::string onDisk = "ready-" + toHex(randomBytes(kNameBytes));
    const int listening = boundAt(onDisk, false);
    CHECK(::setenv("NOTIFY_SOCKET", onDisk.c_str(), 1) == 0);
    announceReady();
    CHECK(received(listening) == kReady);
    CHECK(::close(listening) == 0);

    const std::string abstract = "bazarish-ready-" + toHex(randomBytes(kNameBytes));
    const int hidden = boundAt(abstract, true);
    CHECK(::setenv("NOTIFY_SOCKET", ("@" + abstract).c_str(), 1) == 0);
    announceReady();
    CHECK(received(hidden) == kReady);
    CHECK(::close(hidden) == 0);

    CHECK(::setenv("NOTIFY_SOCKET", ("gone-" + toHex(randomBytes(kNameBytes))).c_str(), 1) == 0);
    CHECK_THROWS(announceReady());

    std::filesystem::current_path(root.parent_path());
    std::filesystem::remove_all(root);
    std::printf("TestServiceReady OK\n");
    return 0;
}
