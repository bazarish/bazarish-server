// Bazarish project (c) 2026
#include "Messages.hpp"

#include <nlohmann/json.hpp>

#include <cctype>
#include <fstream>
#include <set>
#include <stdexcept>

namespace bazarish::service {

namespace {

constexpr const char* kKeyOpens = "{{t.";
constexpr const char* kKeyCloses = "}}";

constexpr int kSecondsPerDay = 24 * 60 * 60;
constexpr std::size_t kLongestBackPath = 512;

std::string valueSlot(const std::size_t index)
{
    return "{" + std::to_string(index) + "}";
}

}  // namespace

Messages::Messages(const std::filesystem::path& catalog)
{
    std::ifstream in(catalog, std::ios::binary);
    if (!in) {
        throw std::runtime_error("cannot open the message catalog " + catalog.string());
    }
    const nlohmann::json doc = nlohmann::json::parse(in);

    std::set<std::string> codes;
    for (const nlohmann::json& one : doc.at("languages")) {
        Language language;
        language.code = one.at("code").get<std::string>();
        language.name = one.at("name").get<std::string>();
        language.rightToLeft = one.value("rtl", false);
        if (language.code.empty() || language.name.empty()) {
            throw std::runtime_error("a language in " + catalog.string() + " has no code or name");
        }
        if (!codes.insert(language.code).second) {
            throw std::runtime_error(
                "the language " + language.code + " is listed twice in " + catalog.string());
        }
        languages_.push_back(std::move(language));
    }
    if (languages_.empty()) {
        throw std::runtime_error("no languages in " + catalog.string());
    }

    for (const auto& [key, written] : doc.at("messages").items()) {
        std::map<std::string, std::string> byCode;
        for (const auto& [code, text] : written.items()) {
            if (codes.count(code) == 0) {
                throw std::runtime_error(key + " in " + catalog.string() + " is written in " + code
                    + ", which this face does not serve");
            }
            byCode[code] = text.get<std::string>();
        }
        for (const std::string& code : codes) {
            if (byCode.count(code) == 0) {
                throw std::runtime_error(
                    key + " in " + catalog.string() + " is missing its " + code + " text");
            }
        }
        texts_[key] = std::move(byCode);
    }
}

bool Messages::knows(const std::string& code) const
{
    for (const Language& language : languages_) {
        if (language.code == code) {
            return true;
        }
    }
    return false;
}

const Language& Messages::language(const std::string& code) const
{
    for (const Language& language : languages_) {
        if (language.code == code) {
            return language;
        }
    }
    throw std::runtime_error("this face does not serve " + code);
}

std::string Messages::codeFor(const std::string& asked) const
{
    return knows(asked) ? asked : languages_.front().code;
}

std::string Messages::text(const std::string& key, const std::string& code,
    const std::vector<std::string>& values) const
{
    const auto written = texts_.find(key);
    if (written == texts_.end()) {
        throw std::runtime_error("no message is written for " + key);
    }
    const auto said = written->second.find(code);
    if (said == written->second.end()) {
        throw std::runtime_error(key + " is not written in " + code);
    }
    std::string text = said->second;
    for (std::size_t index = 0; index < values.size(); ++index) {
        const std::string slot = valueSlot(index);
        for (std::size_t at = text.find(slot); at != std::string::npos;
             at = text.find(slot, at + values[index].size())) {
            text.replace(at, slot.size(), values[index]);
        }
    }
    return text;
}

std::string Messages::translate(const std::string& page, const std::string& code) const
{
    std::string out;
    out.reserve(page.size());
    std::size_t read = 0;
    for (;;) {
        const std::size_t opens = page.find(kKeyOpens, read);
        if (opens == std::string::npos) {
            out.append(page, read, std::string::npos);
            return out;
        }
        const std::size_t keyAt = opens + std::string(kKeyOpens).size();
        const std::size_t closes = page.find(kKeyCloses, keyAt);
        if (closes == std::string::npos) {
            out.append(page, read, std::string::npos);
            return out;
        }
        const std::string key = page.substr(keyAt, closes - keyAt);
        out.append(page, read, opens - read);
        if (texts_.count(key) != 0) {
            out += text(key, code);
        } else {
            out.append(page, opens, closes + std::string(kKeyCloses).size() - opens);
        }
        read = closes + std::string(kKeyCloses).size();
    }
}

std::string languageCookie(const std::string& code)
{
    return "lang=" + code + "; Max-Age=" + std::to_string(kLanguageCookieDays * kSecondsPerDay)
        + "; HttpOnly; SameSite=Lax; Path=/";
}

std::string urlEncode(const std::string& value)
{
    static const char* const kDigits = "0123456789ABCDEF";
    std::string out;
    out.reserve(value.size());
    for (const char letter : value) {
        const unsigned char byte = static_cast<unsigned char>(letter);
        if (std::isalnum(byte) != 0 || letter == '-' || letter == '_' || letter == '.'
            || letter == '~') {
            out.push_back(letter);
        } else {
            out.push_back('%');
            out.push_back(kDigits[byte >> 4]);
            out.push_back(kDigits[byte & 0x0F]);
        }
    }
    return out;
}

std::string sameSitePath(const std::string& asked)
{
    if (asked.empty() || asked.front() != '/' || asked.size() > kLongestBackPath) {
        return "/";
    }
    if (asked.size() > 1 && (asked[1] == '/' || asked[1] == '\\')) {
        return "/";
    }
    for (const char letter : asked) {
        if (static_cast<unsigned char>(letter) <= ' ' || letter == '\\') {
            return "/";
        }
    }
    return asked;
}

}  // namespace bazarish::service
