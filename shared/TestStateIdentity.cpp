// Bazarish project (c) 2026
#include "StateIdentity.hpp"
#include "TestUtil.hpp"

#include <bazarish/Hybrid.hpp>
#include <bazarish/PrivateFile.hpp>

#include <cstdio>
#include <filesystem>

using namespace bazarish;

int main()
try {
    const testutil::ScratchDir scratch("state-identity");
    const std::filesystem::path& root = scratch.path();

    const Key made = server::loadOrCreateSealingKey(root);
    CHECK(hybrid::isSealingKey(made));
    CHECK(server::loadOrCreateSealingKey(root).publicDer() == made.publicDer());
    const Identity identity = server::loadOrCreateIdentity(root);
    CHECK(server::loadOrCreateIdentity(root).fingerprint() == identity.fingerprint());

    const std::filesystem::path classicalOnly = root / "classical";
    std::filesystem::create_directories(classicalOnly);
    writePrivateFile(classicalOnly / "sealing.pem", Key::generateX25519().privatePem());
    CHECK_THROWS(server::loadOrCreateSealingKey(classicalOnly));

    std::printf("TestStateIdentity OK\n");
    return 0;
} catch (...) {
    return testutil::failed();
}
