// Bazarish project (c) 2026
#include "NodeSettings.hpp"

#include <nlohmann/json.hpp>

#include <fstream>
#include <stdexcept>
#include <utility>

namespace bazarish::service {

namespace {

namespace fs = std::filesystem;

// How the config file spells the knobs, so a hand-edited file and a panel-edited
// one are the same file.
const char* const kRegistrationKey = "registration";
const char* const kRequireApprovalKey = "requireApproval";
const char* const kMessageKey = "message";
const char* const kQuotaKey = "freeStorageBytes";
const char* const kTtlDaysKey = "ttlDays";

// The written file replaces the old one only once it is whole, so a crash
// mid-write cannot leave a node without a config.
void writeFileAtomic(const fs::path& path, const std::string& text)
{
    const fs::path temporary = path.string() + ".tmp";
    {
        std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
        if (!out) {
            throw std::runtime_error("cannot write " + temporary.string());
        }
        out << text;
        if (!out) {
            throw std::runtime_error("cannot write " + temporary.string());
        }
    }
    fs::rename(temporary, path);
}

}  // namespace

NodeSettings::NodeSettings(fs::path configPath, Values initial)
    : configPath_(std::move(configPath))
    , values_(std::move(initial))
{
}

NodeSettings::Values NodeSettings::get() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return values_;
}

void NodeSettings::set(const Values& values)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    persist(values);
    values_ = values;
}

void NodeSettings::persist(const Values& values) const
{
    if (configPath_.empty()) {
        throw std::runtime_error("this node was started without a config file to write to");
    }
    // Patch the file rather than rewrite it: everything else in there is the
    // operator's, and a setting the panel does not know about must survive.
    nlohmann::json document = nlohmann::json::object();
    if (fs::exists(configPath_)) {
        std::ifstream in(configPath_);
        if (!in) {
            throw std::runtime_error("cannot read " + configPath_.string());
        }
        document = nlohmann::json::parse(in);
    }
    document[kRegistrationKey][kRequireApprovalKey] = values.requireApproval;
    document[kRegistrationKey][kMessageKey] = values.registrationMessage;
    document[kRegistrationKey][kTtlDaysKey] = values.registrationTtlDays;
    document[kQuotaKey] = values.defaultQuotaBytes;
    writeFileAtomic(configPath_, document.dump(2) + "\n");
}

}  // namespace bazarish::service
