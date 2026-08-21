// Bazarish project (c) 2026
#pragma once

#include <filesystem>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace bazarish::service {

// The portal's web files - the page shell, one template per state of the flow,
// the stylesheet, the logo, the fonts. They sit on disk beside the binary
// instead of inside it, so an operator owns the whole page: not only its colours
// but every word on it. The node fills in the values a template asks for by
// name ({{challenge}}, {{quota}}, ...) and writes nothing else.
//
// Each file is read once and answered from memory afterwards, which also means
// an edit takes effect on restart.
class PortalAssets {
public:
    struct File {
        std::string body;
        std::string contentType;
    };

    // Loads every template and the stylesheet at once: a portal that cannot draw
    // its own pages must say so at start, not on the first visitor.
    explicit PortalAssets(std::filesystem::path directory);

    // A file by its plain name, read on first use. Throws when the name is not a
    // plain file name, when its type is not one the portal serves, or when the
    // file cannot be read.
    const File& file(const std::string& name);

    // A template with its {{placeholders}} filled in from values; a placeholder
    // with no value is left as it stands, so a typo in a template shows up as
    // itself instead of vanishing.
    std::string render(
        const std::string& templateName, const std::map<std::string, std::string>& values);

    // The files the portal publishes: everything in the directory the browser
    // may ask for by name (templates are filled in by the portal, not served).
    std::vector<std::string> published() const;

private:
    std::filesystem::path directory_;
    mutable std::mutex mutex_;
    std::map<std::string, File> cache_;
};

}  // namespace bazarish::service
