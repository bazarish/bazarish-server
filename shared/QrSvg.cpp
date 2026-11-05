// Bazarish project (c) 2026
#include "QrSvg.hpp"

#include <qrencode.h>

#include <memory>
#include <stdexcept>

namespace bazarish::qr {

namespace {

// ISO/IEC 18004: four light modules around the symbol; bit 0 of a module is dark.
constexpr int kQrQuietModules = 4;
constexpr unsigned char kQrDark = 1;

}  // namespace

std::string svg(const std::string& text)
{
    const std::unique_ptr<QRcode, decltype(&QRcode_free)> code(
        QRcode_encodeString8bit(text.c_str(), 0, QR_ECLEVEL_M), &QRcode_free);
    if (!code) {
        throw std::runtime_error("the text does not fit a QR code");
    }
    const int width = code->width;
    const auto dark = [&code, width](const int x, const int y) {
        return (code->data[y * width + x] & kQrDark) != 0;
    };
    std::string path;
    for (int y = 0; y < width; ++y) {
        for (int x = 0; x < width;) {
            if (!dark(x, y)) {
                ++x;
                continue;
            }
            const int from = x;
            while (x < width && dark(x, y)) {
                ++x;
            }
            const std::string run = std::to_string(x - from);
            path += "M" + std::to_string(from + kQrQuietModules) + " "
                + std::to_string(y + kQrQuietModules) + "h" + run + "v1h-" + run + "z";
        }
    }
    const std::string side = std::to_string(width + 2 * kQrQuietModules);
    return "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 " + side + " " + side
        + "\" shape-rendering=\"crispEdges\" aria-hidden=\"true\"><rect width=\"" + side
        + "\" height=\"" + side + "\" fill=\"#fff\"/><path fill=\"#000\" d=\"" + path
        + "\"/></svg>";
}

}  // namespace bazarish::qr
