// Bazarish project (c) 2026
#pragma once

#include <bazarish/I2p.hpp>

#include <filesystem>
#include <string>

namespace bazarish::facade {

struct FacadeAddress {
    bazarish::i2p::Keys keys;

    std::string address() const;
};

FacadeAddress loadAddress(const std::filesystem::path& stateDir);

FacadeAddress mintAddress(const std::filesystem::path& stateDir);

}  // namespace bazarish::facade
