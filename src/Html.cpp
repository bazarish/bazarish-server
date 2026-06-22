// Bazarish project (c) 2026
#include "Html.hpp"

#include <array>
#include <cstdio>

namespace bazarish::admin {

std::string htmlEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (const char c : s) {
        switch (c) {
        case '&':
            out += "&amp;";
            break;
        case '<':
            out += "&lt;";
            break;
        case '>':
            out += "&gt;";
            break;
        case '"':
            out += "&quot;";
            break;
        case '\'':
            out += "&#39;";
            break;
        default:
            out += c;
        }
    }
    return out;
}

std::string bytesHuman(const std::uint64_t bytes)
{
    const std::array<const char*, 5> units = {"B", "KiB", "MiB", "GiB", "TiB"};
    double value = static_cast<double>(bytes);
    std::size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < units.size()) {
        value /= 1024.0;
        ++unit;
    }
    char buffer[32];
    std::snprintf(
        buffer, sizeof(buffer), value < 10.0 ? "%.1f %s" : "%.0f %s", value, units[unit]);
    return buffer;
}

std::string htmlPage(const std::string& title, const std::string& body, const bool wide)
{
    return "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
           "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
           "<title>"
        + htmlEscape(title)
        + " - Bazarish admin</title><style>"
          ":root{color-scheme:dark}"
          "*{box-sizing:border-box}"
          "body{margin:0;min-height:100vh;display:flex;justify-content:center;"
          "align-items:flex-start;background:#14161a;color:#e6e8eb;"
          "font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}"
          "main{width:100%;max-width:48rem;margin:2.5rem 1rem;padding:1.75rem;"
          "background:#1c1f24;border:1px solid #2a2f37;border-radius:14px}"
          "main.wide{max-width:72rem}"
          "h1{font-size:1.25rem;margin:0 0 1.25rem}h2{font-size:1.05rem;margin:1.5rem 0 .5rem}"
          "a{color:#7cc0ff}label{display:block;margin:.75rem 0 .25rem;font-size:.9rem;color:#aeb4bd}"
          "input,textarea,select{width:100%;padding:.6rem;background:#0f1115;color:#e6e8eb;"
          "border:1px solid #333a44;border-radius:8px;font:inherit}"
          "textarea{resize:vertical}"
          "button{margin-top:1rem;padding:.6rem 1.1rem;background:#2f6feb;color:#fff;border:0;"
          "border-radius:8px;font:inherit;cursor:pointer}button:hover{background:#3b7df0}"
          "pre{background:#0f1115;border:1px solid #2a2f37;border-radius:8px;padding:.75rem;"
          "overflow-x:auto;font-size:.85rem;white-space:pre-wrap;word-break:break-all}"
          "code{font-size:.85rem;word-break:break-all}"
          "table{width:100%;border-collapse:collapse;font-size:.9rem}"
          "th,td{text-align:left;padding:.4rem .5rem;border-bottom:1px solid #2a2f37}"
          ".flash{background:#16331f;border:1px solid #2c6b3f;color:#bfe9cd;padding:.6rem .8rem;"
          "border-radius:8px}.err{background:#3a1b1f;border:1px solid #7a2b34;color:#f3c2c8;"
          "padding:.6rem .8rem;border-radius:8px}"
          ".svc{border:1px solid #2a2f37;border-radius:10px;padding:.75rem 1rem;margin:.6rem 0}"
          ".muted{color:#8b929c;font-size:.85rem}"
          ".up{color:#7ee08a;font-weight:600}.down{color:#f3838e;font-weight:600}"
          "</style></head><body><main"
        + std::string(wide ? " class=\"wide\"" : "")
        + "><h1>Bazarish admin panel</h1>" + body + "</main></body></html>";
}

}  // namespace bazarish::admin
