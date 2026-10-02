// Bazarish project (c) 2026
#pragma once

#include <bazarish/Portal.hpp>

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

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
        // What a client is told when it reaches a server it has no account on:
        // the operator's own words about this node and how to get one.
        std::string portalMessage;
        // Who the portal says it is when it asks a user to sign in: the name,
        // the address and the role a client shows before signing, which the user
        // compares with the address bar. Live, because renaming a deployment or
        // moving it behind another address must not need a restart.
        LoginConsumer loginConsumer;
        // Where clients reach this server: I2P addresses, because that is the only
        // way a client ever talks to it. The descriptor a user pastes is these
        // plus the server's fingerprint, so the operator edits the list and not
        // the string.
        std::vector<std::string> facades;
        // Where a client with no I2P router yet fetches a slice of netdb to start
        // from. Clearnet addresses, and nothing else is served on them.
        std::vector<std::string> reseeds;
        // Where a person is told they can onboard: the portal's public links,
        // handed to clients by the discovery endpoint.
        std::vector<std::string> portalLinks;
        // How much this node says. Applied the moment it is set.
        std::string logLevel;
        // The three addresses this node was started on: its operator API, its
        // portal, and the messaging server it is bound to. Read at start, so a
        // change to any of them waits for a restart.
        std::string listenHost;
        int listenPort = 0;
        std::string portalListenHost;
        int portalListenPort = 0;
        std::string messagingHost;
        int messagingPort = 0;
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
