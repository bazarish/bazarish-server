// Bazarish project (c) 2026
#include "LoginRelay.hpp"

#include <bazarish/JsonRead.hpp>
#include <bazarish/Links.hpp>
#include <bazarish/Portal.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>

namespace bazarish::loginrelay {

std::optional<std::string> nonceAfter(const std::string& path, const std::string& prefix)
{
    if (path.rfind(prefix, 0) != 0) {
        return std::nullopt;
    }
    const std::string nonce = path.substr(prefix.size());
    const bool hex = nonce.size() == kNonceChars
        && std::all_of(nonce.begin(), nonce.end(),
            [](const char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
    if (!hex) {
        return std::nullopt;
    }
    return nonce;
}

std::string nonceOf(const std::string& challenge)
{
    return bazarish::parseJson(service::decodeLoginChallenge(challenge))
        .at("nonce")
        .get<std::string>();
}

std::string callbackUrl(const std::string& facade)
{
    return service::kLoginCallbackScheme + facade + kCallbackPath;
}

std::string challengeLink(const std::string& facade, const std::string& nonce)
{
    return schemeLink(std::string(kSignKind) + service::kLoginLinkField + facade
        + kChallengePrefix + nonce);
}

}  // namespace bazarish::loginrelay
