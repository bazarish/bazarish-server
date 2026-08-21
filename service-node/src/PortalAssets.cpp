// Bazarish project (c) 2026
#include "PortalAssets.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace bazarish::service {

namespace {

// What the portal serves out of its asset directory, and as what. A file of any
// other type is not published: the directory holds a site, not a file share.
const std::map<std::string, std::string>& contentTypes()
{
    static const std::map<std::string, std::string> kTypes = {
        {".css", "text/css; charset=utf-8"},
        {".svg", "image/svg+xml"},
        {".png", "image/png"},
        {".ico", "image/x-icon"},
        {".woff2", "font/woff2"},
        {".txt", "text/plain; charset=utf-8"},
    };
    return kTypes;
}

// The shell every page is poured into. It is filled in by the portal, so it is
// not published as a file of its own.
const char* const kShellFile = "page.html";
const char* const kStyleFile = "style.css";
const char* const kShellContentType = "text/html; charset=utf-8";

const char* const kTitleToken = "{{title}}";
const char* const kSubtitleToken = "{{subtitle}}";
const char* const kContentToken = "{{content}}";

std::string readFile(const std::filesystem::path& path)
{
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw std::runtime_error("portal asset cannot be read: " + path.string());
    }
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    return buffer.str();
}

void substitute(std::string& text, const std::string& token, const std::string& value)
{
    for (std::size_t at = text.find(token); at != std::string::npos;
         at = text.find(token, at + value.size())) {
        text.replace(at, token.size(), value);
    }
}

}  // namespace

PortalAssets::PortalAssets(std::filesystem::path directory)
    : directory_(std::move(directory))
{
    if (!std::filesystem::is_directory(directory_)) {
        throw std::runtime_error("portal assets directory not found: " + directory_.string());
    }
    const std::lock_guard<std::mutex> lock(mutex_);
    cache_.emplace(kShellFile, File{readFile(directory_ / kShellFile), kShellContentType});
    cache_.emplace(kStyleFile,
        File{readFile(directory_ / kStyleFile), contentTypes().at(".css")});
}

const PortalAssets::File& PortalAssets::file(const std::string& name)
{
    const std::filesystem::path asked(name);
    if (name.empty() || asked.filename() != asked) {
        throw std::runtime_error("portal asset name is not a plain file name: " + name);
    }
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto cached = cache_.find(name);
    if (cached != cache_.end()) {
        return cached->second;
    }
    const auto type = contentTypes().find(asked.extension().string());
    if (type == contentTypes().end()) {
        throw std::runtime_error("portal does not serve this type of file: " + name);
    }
    return cache_.emplace(name, File{readFile(directory_ / name), type->second}).first->second;
}

std::vector<std::string> PortalAssets::published() const
{
    std::vector<std::string> names;
    for (const std::filesystem::directory_entry& entry :
        std::filesystem::directory_iterator(directory_)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        const std::string name = entry.path().filename().string();
        if (name == kShellFile || contentTypes().count(entry.path().extension().string()) == 0) {
            continue;
        }
        names.push_back(name);
    }
    return names;
}

std::string PortalAssets::page(
    const std::string& title, const std::string& subtitle, const std::string& content)
{
    std::string html = file(kShellFile).body;
    substitute(html, kTitleToken, title);
    substitute(html, kSubtitleToken, subtitle);
    substitute(html, kContentToken, content);
    return html;
}

}  // namespace bazarish::service
