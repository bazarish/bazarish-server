// Bazarish project (c) 2026
#include "StateIdentity.hpp"

#include <bazarish/Hybrid.hpp>
#include <bazarish/PrivateFile.hpp>

#include <stdexcept>

namespace bazarish::server {

Identity loadOrCreateIdentity(const std::filesystem::path& stateDir)
{
    const std::filesystem::path path = stateDir / "identity.pem";
    if (std::filesystem::exists(path)) {
        Identity identity = Identity::fromPrivatePem(readFileText(path));
        if (!identity.classical().isA(kClassicalSigningAlgorithm)
            || !identity.pq().isA(kPqSigningAlgorithm)) {
            throw std::runtime_error(path.string()
                + " is not an Ed25519 and ML-DSA-65 identity: refusing to start with it");
        }
        return identity;
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
        Key key = Key::fromPrivatePem(readFileText(path));
        if (!hybrid::isSealingKey(key)) {
            throw std::runtime_error(path.string()
                + " is not an X25519 and ML-KEM-768 sealing key: refusing to start with it");
        }
        return key;
    }
    Key key = Key::generateSealing();
    std::filesystem::create_directories(stateDir);
    writePrivateFile(path, key.privatePem());
    return key;
}

}  // namespace bazarish::server
