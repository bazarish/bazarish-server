// Bazarish project (c) 2026
#pragma once

#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace bazarish::service {

// One language this face is served in.
struct Language {
    std::string code;        // what the cookie and the switch url carry
    std::string name;        // the language's own name, as the switch prints it
    bool rightToLeft = false;
};

// The words of this face in every language it offers. The catalog is read once
// at start and is either complete or refused: a page that cannot be drawn in a
// language the switch offers is a fault of the deployment, not something for a
// visitor to find.
//
// The file is JSON beside the templates:
//
//   {"languages": [{"code": "en", "name": "English"},
//                  {"code": "ar", "name": "...", "rtl": true}],
//    "messages": {"deposit.title": {"en": "deposit", "ar": "..."}}}
//
// A text may carry {0}, {1} ... for the values the caller passes. Languages do
// not agree on word order, so every value a sentence needs is numbered rather
// than glued to one end of it.
class Messages {
public:
    explicit Messages(const std::filesystem::path& catalog);

    // In the order the switch lists them; the first is what a visitor who has
    // chosen nothing is served.
    const std::vector<Language>& languages() const { return languages_; }
    bool knows(const std::string& code) const;
    // Throws when the code is not served here.
    const Language& language(const std::string& code) const;

    // The code this face answers in for what a cookie asked: the asked language
    // when it is served here, the first one listed otherwise. A cookie outlives
    // a deployment that stopped serving its language.
    std::string codeFor(const std::string& asked) const;

    // Throws when the key is not in the catalog, which is a fault in the code
    // that asked for it.
    std::string text(const std::string& key, const std::string& code,
        const std::vector<std::string>& values = {}) const;

    // Every {{t.key}} in a drawn page, replaced by its text in this language. An
    // unknown key is left standing as itself, the way WebAssets leaves a
    // placeholder it has no value for: a typo shows up on the page instead of
    // taking the page down.
    std::string translate(const std::string& page, const std::string& code) const;

private:
    std::vector<Language> languages_;
    std::map<std::string, std::map<std::string, std::string>> texts_;
};

// How long a chosen language is remembered: a visitor who has picked one is not
// asked again this year.
inline constexpr int kLanguageCookieDays = 365;

// The cookie the language switch leaves behind. SameSite is Lax rather than
// Strict because a Strict cookie is not sent when a visitor arrives by somebody
// else's link, which would show them a language they did not choose.
std::string languageCookie(const std::string& code);

// A value as it may stand in a query string: everything but the unreserved set
// is percent-encoded, so a path carrying its own query survives being carried
// inside one.
std::string urlEncode(const std::string& value);

// The path the switch returns to, out of what its url asked for. Only a path of
// this face is let through: a value naming a scheme, a host or a newline would
// turn the switch into an open redirect or into a header of its own. Anything
// else becomes "/".
std::string sameSitePath(const std::string& asked);

}  // namespace bazarish::service
