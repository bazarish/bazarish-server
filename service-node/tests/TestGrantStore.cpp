// Bazarish project (c) 2026
#include "GrantStore.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

using namespace bazarish;
using namespace bazarish::service;

int main()
{
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() / ("bazarish-grants-" + toHex(randomBytes(8)));
    const std::string user = Identity::generate().fingerprint();

    {
        GrantStore grants(root);
        CHECK(!grants.peekSubscription(user).has_value());

        grants.grantSubscription(user, 5ULL * 1024 * 1024 * 1024, 1000);
        const std::optional<GrantStore::SubscriptionGrant> peeked = grants.peekSubscription(user);
        CHECK(peeked.has_value());
        CHECK(peeked->quotaBytes == 5ULL * 1024 * 1024 * 1024);
        CHECK(peeked->grantedAt == 1000);
    }
    {
        // Persistence across reopen, then a one-shot take.
        GrantStore grants(root);
        const std::optional<GrantStore::SubscriptionGrant> taken = grants.takeSubscription(user);
        CHECK(taken.has_value());
        CHECK(taken->quotaBytes == 5ULL * 1024 * 1024 * 1024);
        CHECK(!grants.peekSubscription(user).has_value());     // consumed
        CHECK(!grants.takeSubscription(user).has_value());     // nothing left
    }

    {
        // Moderated registration: pending until approved, and the approval
        // outlives the one-shot subscription grant.
        GrantStore grants(root);
        const std::string moderated = Identity::generate().fingerprint();
        CHECK(!grants.peekApproval(moderated).has_value());

        grants.recordRegistration(moderated, 2000, false);
        std::optional<GrantStore::Approval> approval = grants.peekApproval(moderated);
        CHECK(approval.has_value());
        CHECK(approval->pending());
        CHECK(approval->requestedAt == 2000);

        // A renewal must not restart the deadline.
        grants.recordRegistration(moderated, 9000, false);
        approval = grants.peekApproval(moderated);
        CHECK(approval->requestedAt == 2000);
        CHECK(approval->pending());

        std::vector<std::string> pending = grants.pendingUsers();
        CHECK(pending.size() == 1);
        CHECK(pending.front() == moderated);

        grants.approve(moderated, 3000);
        approval = grants.peekApproval(moderated);
        CHECK(!approval->pending());
        CHECK(approval->approvedAt == 3000);
        CHECK(grants.pendingUsers().empty());

        // Approving twice keeps the first timestamp.
        grants.approve(moderated, 4000);
        CHECK(grants.peekApproval(moderated)->approvedAt == 3000);

        grants.erase(moderated);
        CHECK(!grants.peekApproval(moderated).has_value());
    }
    {
        // Open registration approves on creation.
        GrantStore grants(root);
        const std::string open = Identity::generate().fingerprint();
        grants.recordRegistration(open, 5000, true);
        CHECK(!grants.peekApproval(open)->pending());
        CHECK(grants.pendingUsers().empty());
        grants.erase(open);
    }

    fs::remove_all(root);
    std::printf("TestGrantStore: all checks passed\n");
    return 0;
}
