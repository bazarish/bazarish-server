// Bazarish project (c) 2026
#pragma once

#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace bazarish::service {

struct Language {
    std::string code;
    std::string name;
    bool rightToLeft = false;
};

class Messages {
public:
    explicit Messages(const std::filesystem::path& catalog);

    const std::vector<Language>& languages() const { return languages_; }
    bool knows(const std::string& code) const;
    const Language& language(const std::string& code) const;

    std::string codeFor(const std::string& asked) const;

    std::string text(const std::string& key, const std::string& code,
        const std::vector<std::string>& values = {}) const;

    std::string translate(const std::string& page, const std::string& code) const;

private:
    std::vector<Language> languages_;
    std::map<std::string, std::map<std::string, std::string>> texts_;
};

inline constexpr int kLanguageCookieDays = 365;

std::string languageCookie(const std::string& code);

std::string urlEncode(const std::string& value);

std::string sameSitePath(const std::string& asked);

}  // namespace bazarish::service
