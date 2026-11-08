// Bazarish project (c) 2026
#pragma once

#include <bazarish/WebAssets.hpp>

#include <cstddef>
#include <string>

namespace bazarish::server {

inline constexpr std::size_t kSignInTokenBytes = 16;

std::string newSignInToken();
// The code a phone scans for a challenge that calls back to the facade.
std::string signInScan(
    WebAssets& assets, const std::string& facade, const std::string& challenge);

}  // namespace bazarish::server
