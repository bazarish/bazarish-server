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
void writeKeys(const fs::path& keyPath, const bazarish::i2p::Keys& keys)
{
    const bazarish::Bytes blob = keys.blob();
    bazarish::writePrivateFile(keyPath, std::string(blob.begin(), blob.end()));
}

}  // namespace

std::string FacadeAddress::address() const
{
    return bazarish::i2p::routingHost(keys.publicBase64());
}

FacadeAddress loadAddress(const fs::path& stateDir)
{
    fs::create_directories(stateDir);
    const fs::path keyPath = stateDir / kDestinationKeyFile;
    if (!fs::exists(keyPath)) {
        writeKeys(keyPath, bazarish::i2p::Keys::generate());
    }
    const std::string raw = bazarish::readFileText(keyPath);
    return FacadeAddress{bazarish::i2p::Keys::fromBlob(bazarish::Bytes(raw.begin(), raw.end()))};
}

FacadeAddress mintAddress(const fs::path& stateDir)
{
    fs::create_directories(stateDir);
    FacadeAddress minted{bazarish::i2p::Keys::generate()};
    writeKeys(stateDir / kDestinationKeyFile, minted.keys);
    return minted;
}

}  // namespace bazarish::facade
