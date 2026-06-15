// Bazarish project (c) 2026
#include "InvoiceStore.hpp"

#include <nlohmann/json.hpp>

#include <fstream>
#include <stdexcept>
#include <utility>

namespace bazarish::service {

namespace {

namespace fs = std::filesystem;

nlohmann::json readMap(const fs::path& path)
{
    if (!fs::exists(path)) {
        return nlohmann::json::object();
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open " + path.string());
    }
    return nlohmann::json::parse(in);
}

void writeMap(const fs::path& path, const nlohmann::json& map)
{
    const fs::path temporary = path.parent_path() / (path.filename().string() + ".tmp");
    {
        std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
        if (!out) {
            throw std::runtime_error("failed to open " + temporary.string());
        }
        out << map.dump();
        if (!out) {
            throw std::runtime_error("failed to write " + temporary.string());
        }
    }
    fs::rename(temporary, path);
}

}  // namespace

InvoiceStore::InvoiceStore(fs::path path)
    : path_(std::move(path))
{
    fs::create_directories(path_.parent_path());
}

void InvoiceStore::put(const std::string& invoiceId, const std::string& user)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    nlohmann::json map = readMap(path_);
    map[invoiceId] = user;
    writeMap(path_, map);
}

std::optional<std::string> InvoiceStore::user(const std::string& invoiceId)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const nlohmann::json map = readMap(path_);
    if (!map.contains(invoiceId)) {
        return std::nullopt;
    }
    return map.at(invoiceId).get<std::string>();
}

}  // namespace bazarish::service
