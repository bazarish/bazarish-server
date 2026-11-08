// Bazarish project (c) 2026
#include "SignInScan.hpp"

#include "LoginRelay.hpp"
#include "QrSvg.hpp"

#include <bazarish/Bytes.hpp>

namespace bazarish::server {

std::string newSignInToken()
{
    return toHex(randomBytes(kSignInTokenBytes));
}

std::string signInScan(
    WebAssets& assets, const std::string& facade, const std::string& challenge)
{
    const std::string nonce = loginrelay::nonceOf(challenge);
    return assets.render("signin-scan.html",
        {
            {"qr", qr::svg(loginrelay::challengeLink(facade, nonce))},
            {"nonce", nonce},
        });
}

}  // namespace bazarish::server
