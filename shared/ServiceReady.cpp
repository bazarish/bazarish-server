// Bazarish project (c) 2026
#include "ServiceReady.hpp"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

namespace bazarish {

namespace {

constexpr const char* kNotifySocketVariable = "NOTIFY_SOCKET";
constexpr std::string_view kReady = "READY=1";
// sd_notify(3): a leading '@' names a socket in the abstract namespace.
constexpr char kAbstractMark = '@';

}  // namespace

void announceReady()
{
    const char* const named = std::getenv(kNotifySocketVariable);
    if (named == nullptr || *named == '\0') {
        return;
    }
    const std::string path(named);
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (path.size() >= sizeof(address.sun_path)) {
        throw std::runtime_error(std::string(kNotifySocketVariable)
            + " names a socket longer than a socket address holds: " + path);
    }
    std::memcpy(address.sun_path, path.data(), path.size());
    if (path.front() == kAbstractMark) {
        address.sun_path[0] = '\0';
    }
    const int fd = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        throw std::system_error(errno, std::generic_category(), "no socket to tell systemd");
    }
    const socklen_t length = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + path.size());
    const ssize_t sent = ::sendto(fd, kReady.data(), kReady.size(), MSG_NOSIGNAL,
        reinterpret_cast<const sockaddr*>(&address), length);
    const int sendError = errno;
    if (::close(fd) != 0) {
        throw std::system_error(errno, std::generic_category(), "the socket to systemd");
    }
    if (sent != static_cast<ssize_t>(kReady.size())) {
        throw std::system_error(sendError, std::generic_category(),
            "systemd was not told this service is ready at " + path);
    }
}

}  // namespace bazarish
