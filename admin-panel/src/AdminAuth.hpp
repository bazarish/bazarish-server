// Bazarish project (c) 2026
#pragma once

#include "PanelSettings.hpp"

#include <bazarish/LoginChallenge.hpp>
#include <bazarish/Portal.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace bazarish::admin {

// The panel login policy: a challenge it issued, a valid signature over it, and a
// signer that matches one of the configured admin identities.
//
// The challenge store and the wire contract are the common ones every portal uses,
// so what the panel asks an operator to sign is what a client already knows how to
// show. The secret binding those challenges is minted per run: a restart
// invalidates outstanding ones, and there is nothing to configure or to leak.
class AdminAuth {
public:
    explicit AdminAuth(std::shared_ptr<PanelSettings> settings);

    std::string issueChallenge(std::int64_t now);

    // Verifies a challenge this panel issued and the signature over it, and
    // returns the signer - whoever they are. This is what the setup wizard
    // needs: an unclaimed panel has no list for anyone to be on yet.
    std::string verify(const std::string& challenge, const std::string& blob, std::int64_t now);

    // Completes a login: verify, and then require the signer to be one of the
    // administrators the panel currently has. Returns the admin fingerprint on
    // success; throws otherwise.
    std::string login(const std::string& challenge, const std::string& blob, std::int64_t now);

private:
    // The issuer, holding the words the panel says it is now: an operator can
    // rename it from the panel itself.
    service::LoginChallenge& challenges();

    std::shared_ptr<PanelSettings> settings_;
    service::LoginChallenge challenges_;
};

}  // namespace bazarish::admin
