// Bazarish project (c) 2026
#pragma once

#include <bazarish/LoginChallenge.hpp>
#include <bazarish/Portal.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace bazarish::admin {

// The panel login policy: a challenge it issued, a valid signature over it, and a
// signer that matches one of the configured admin identities.
//
// The challenge store and the wire contract are the common ones every portal
// uses, so what the panel asks an operator to sign is what a client already
// knows how to show: base64(JSON {v, nonce, ts, consumer, tag}), naming this
// panel, signed as the body of the canonical BZ-LOGIN request. The secret
// binding those challenges is minted per run - a restart simply invalidates
// outstanding ones, and there is nothing to configure or to leak.
class AdminAuth {
public:
    AdminAuth(service::LoginConsumer consumer, std::vector<std::string> adminFingerprints);

    std::string issueChallenge(std::int64_t now);

    // Completes a login. The store verifies the signature over a challenge this
    // panel issued (version, consumer, freshness, tag, single use); this then
    // requires the signer to be a configured admin. Returns the admin
    // fingerprint on success; throws otherwise.
    std::string login(const std::string& challenge, const std::string& blob, std::int64_t now);

private:
    service::LoginChallenge challenges_;
    std::vector<std::string> adminFingerprints_;
};

}  // namespace bazarish::admin
