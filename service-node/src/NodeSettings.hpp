// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>

namespace bazarish::service {

// The knobs an operator turns while the node runs: whether an account is served
// on registration or waits for them, what a waiting user is told, and how much
// storage a new account gets. They are shared by the account API and the portal
// so the two can never disagree, and written back to the node's config file so a
// restart keeps what the operator chose.
class NodeSettings {
public:
    struct Values {
        bool requireApproval = false;
        std::string registrationMessage;
        std::uint64_t defaultQuotaBytes = 0;
        // How long an account is kept without a delegated destination before
        // the node drops it. The delegation is the only sign of life a server
        // has, so this one number covers a client that stopped running, a
        // registration nobody redeemed and an account no operator approved.
        // 0 keeps them forever.
        std::int64_t idleDeleteDays = 0;
    };

    NodeSettings(std::filesystem::path configPath, Values initial);

    Values get() const;

    // Applies the values and writes them to the config file. Throws when the
    // file cannot be written: an operator must not be told a change stuck when
    // it would vanish at the next restart.
    void set(const Values& values);

private:
    void persist(const Values& values) const;

    std::filesystem::path configPath_;
    mutable std::mutex mutex_;
    Values values_;
};

}  // namespace bazarish::service
