// Bazarish project (c) 2026
#pragma once

#include <cstddef>
#include <optional>
#include <string>

namespace bazarish::loginrelay {

inline constexpr char kCallbackPath[] = "/login/callback";
inline constexpr char kChallengePrefix[] = "/login/c/";
// LoginChallenge's nonce: 16 random bytes in hex.
inline constexpr std::size_t kNonceChars = 32;

std::optional<std::string> nonceAfter(const std::string& path, const std::string& prefix);

std::string nonceOf(const std::string& challenge);

std::string callbackUrl(const std::string& facade);

std::string challengeLink(const std::string& facade, const std::string& nonce);

}  // namespace bazarish::loginrelay
