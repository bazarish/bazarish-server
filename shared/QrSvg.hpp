// Bazarish project (c) 2026
#pragma once

#include <string>

namespace bazarish::qr {

// Throws when the text does not fit a QR symbol.
std::string svg(const std::string& text);

}  // namespace bazarish::qr
