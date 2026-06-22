// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <string>

namespace bazarish::admin {

// Escapes a string for safe interpolation into HTML text or a quoted attribute.
std::string htmlEscape(const std::string& s);

// A human-readable byte size (powers of 1024), e.g. "12.0 MiB".
std::string bytesHuman(std::uint64_t bytes);

// Wraps a page body in the shared document shell. All styling is inline so the
// panel pulls in no third-party resource.
std::string htmlPage(const std::string& title, const std::string& body);

}  // namespace bazarish::admin
