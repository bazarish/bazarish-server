// Bazarish project (c) 2026
#pragma once

#include <string>

namespace bazarish::qr {

// The text as a black-on-white QR code in one SVG path; throws when it does not fit a symbol.
std::string svg(const std::string& text);

}  // namespace bazarish::qr
