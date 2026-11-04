// Bazarish project (c) 2026
#include "StateIdentity.hpp"

#include <bazarish/PrivateFile.hpp>

namespace bazarish::server {

Identity loadOrCreateIdentity(const std::filesystem::path& stateDir)
{
    const std::filesystem::path path = stateDir / "identity.pem";
    if (std::filesystem::exists(path)) {
        return Identity::fromPrivatePem(readFileText(path));
    }
    Identity identity = Identity::generate();
    std::filesystem::create_directories(stateDir);
    writePrivateFile(path, identity.privatePem());
    return identity;
}

Key loadOrCreateSealingKey(const std::filesystem::path& stateDir)
{
    const std::filesystem::path path = stateDir / "sealing.pem";
    if (std::filesystem::exists(path)) {
        return Key::fromPrivatePem(readFileText(path));
    }
    Key key = Key::generateSealing();
    std::filesystem::create_directories(stateDir);
    writePrivateFile(path, key.privatePem());
    return key;
}

}  // namespace bazarish::server
