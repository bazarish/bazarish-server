// Bazarish project (c) 2026
#include "FacadeAddress.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/PrivateFile.hpp>

#include <stdexcept>
#include <string>

namespace bazarish::facade {

namespace {

namespace fs = std::filesystem;

constexpr const char* kDestinationKeyFile = "facade-dest-0.key";
constexpr const char* kBasePathFile = "facade-path";
constexpr std::size_t kBasePathBytes = 16;

bool isValidBasePath(const std::string& path)
{
    if (path.empty() || path.front() != '/' || path.back() == '/') {
        return false;
    }
    return path.find_first_of("?# \r\n") == std::string::npos;
}

std::string newBasePath()
{
    std::string path = "/";
    path += bazarish::toHex(bazarish::randomBytes(kBasePathBytes));
    return path;
}

void writeKeys(const fs::path& keyPath, const bazarish::i2p::Keys& keys)
{
    const bazarish::Bytes blob = keys.blob();
    bazarish::writePrivateFile(keyPath, std::string(blob.begin(), blob.end()));
}

}  // namespace

std::string FacadeAddress::url() const
{
    std::string url = "http://";
    url += bazarish::i2p::routingHost(keys.publicBase64());
    url += basePath;
    return url;
}

FacadeAddress loadAddress(const fs::path& stateDir)
{
    fs::create_directories(stateDir);
    const fs::path keyPath = stateDir / kDestinationKeyFile;
    const fs::path pathPath = stateDir / kBasePathFile;
    if (!fs::exists(keyPath)) {
        writeKeys(keyPath, bazarish::i2p::Keys::generate());
    }
    if (!fs::exists(pathPath)) {
        bazarish::writePrivateFile(pathPath, newBasePath());
    }
    const std::string raw = bazarish::readFileText(keyPath);
    const std::string basePath = bazarish::readFileText(pathPath);
    if (!isValidBasePath(basePath)) {
        throw std::runtime_error(pathPath.string()
            + " holds no secret path: it is one line such as /0966179fb196, with no"
              " trailing slash, query or newline");
    }
    return FacadeAddress{
        bazarish::i2p::Keys::fromBlob(bazarish::Bytes(raw.begin(), raw.end())), basePath};
}

FacadeAddress mintAddress(const fs::path& stateDir)
{
    fs::create_directories(stateDir);
    FacadeAddress minted{bazarish::i2p::Keys::generate(), newBasePath()};
    writeKeys(stateDir / kDestinationKeyFile, minted.keys);
    bazarish::writePrivateFile(stateDir / kBasePathFile, minted.basePath);
    return minted;
}

}  // namespace bazarish::facade
