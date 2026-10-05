// Bazarish project (c) 2026
#pragma once

#include "PanelSettings.hpp"

#include <bazarish/LoginChallenge.hpp>
#include <bazarish/Portal.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace bazarish::admin {

class AdminAuth {
public:
    explicit AdminAuth(std::shared_ptr<PanelSettings> settings);

    std::string issueChallenge(std::int64_t now);

    std::string verify(const std::string& challenge, const std::string& blob, std::int64_t now);

    std::string login(const std::string& challenge, const std::string& blob, std::int64_t now);

private:
    service::LoginChallenge& challenges();

    std::shared_ptr<PanelSettings> settings_;
    service::LoginChallenge challenges_;
};

}  // namespace bazarish::admin
