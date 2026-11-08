// Bazarish project (c) 2026
#include "QrSvg.hpp"
#include "TestUtil.hpp"

#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>

using bazarish::qr::svg;

namespace {

// QR version 1 is 21 modules a side; four quiet modules on each edge make 29.
constexpr const char* kVersionOneViewBox = "viewBox=\"0 0 29 29\"";
// Version 40 at level M holds 2331 bytes.
constexpr std::size_t kTooLongForAnySymbol = 4000;

}  // namespace

int main()
{
    const std::string small = svg("bazarish");
    CHECK(small.starts_with("<svg "));
    CHECK(small.find(kVersionOneViewBox) != std::string::npos);
    CHECK(small.find("d=\"M4 4h7v1h-7z") != std::string::npos);
    CHECK(small.find("</svg>") == small.size() - std::string("</svg>").size());

    const std::string invite = "https://bazari.sh/#invite?" + std::string(1500, 'a');
    CHECK(svg(invite).size() > small.size());

    bool refused = false;
    try {
        svg(std::string(kTooLongForAnySymbol, 'a'));
    } catch (const std::runtime_error&) {
        refused = true;
    }
    CHECK(refused);
    return 0;
}
