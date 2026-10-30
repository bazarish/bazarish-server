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
    writePrivateFile(path, identity.privatePem());
    return identity;
}

}  // namespace bazarish::server
