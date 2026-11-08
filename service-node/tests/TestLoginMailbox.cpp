// Bazarish project (c) 2026
#include "LoginMailbox.hpp"
#include "TestUtil.hpp"

#include <LoginRelay.hpp>

#include <bazarish/KeyedSeal.hpp>
#include <bazarish/LoginChallenge.hpp>

#include <cstdio>
#include <cstdlib>
#include <string>

namespace {

using bazarish::service::LoginMailbox;

constexpr std::int64_t kNow = 1800000000;
constexpr std::int64_t kWindow = 300;

}  // namespace

const bazarish::Bytes kKey = bazarish::newLinkKey();

int main()
{
    bazarish::service::LoginChallenge site("site-secret",
        bazarish::service::LoginConsumer{"Bazarish server", {"https://portal.example"}, "Account owner"});
    const std::string challenge = site.issue(kNow);
    const std::string other = site.issue(kNow);
    const std::string nonce = bazarish::loginrelay::nonceOf(challenge);

    {
        LoginMailbox mailbox(kWindow);
        CHECK(!mailbox.held(nonce, kNow).has_value());
        CHECK(!mailbox.deliver(nonce, challenge, "blob", kNow));
        CHECK(mailbox.expect(challenge, "token", kKey, kNow));
        CHECK(mailbox.held(nonce, kNow)->challenge == challenge);
        CHECK(mailbox.held(nonce, kNow)->key == kKey);
        CHECK(mailbox.claim(nonce, "token", kNow).state == LoginMailbox::State::eWaiting);
        CHECK(mailbox.claim(nonce, "stranger", kNow).state == LoginMailbox::State::eGone);
        CHECK(mailbox.claim(nonce, "", kNow).state == LoginMailbox::State::eGone);
        CHECK(!mailbox.deliver(nonce, other, "blob", kNow));
        CHECK(mailbox.deliver(nonce, challenge, "blob", kNow));
        CHECK(!mailbox.deliver(nonce, challenge, "second", kNow));
        CHECK(mailbox.claim(nonce, "stranger", kNow).state == LoginMailbox::State::eGone);
        const LoginMailbox::Claim taken = mailbox.claim(nonce, "token", kNow);
        CHECK(taken.state == LoginMailbox::State::eSigned);
        CHECK(taken.challenge == challenge && taken.blob == "blob");
        CHECK(mailbox.claim(nonce, "token", kNow).state == LoginMailbox::State::eGone);
    }

    {
        LoginMailbox mailbox(kWindow);
        CHECK(mailbox.expect(challenge, "token", kKey, kNow));
        CHECK(mailbox.claim(nonce, "token", kNow + kWindow).state == LoginMailbox::State::eWaiting);
        CHECK(!mailbox.held(nonce, kNow + kWindow + 1).has_value());
        CHECK(!mailbox.deliver(nonce, challenge, "blob", kNow + kWindow + 1));
        CHECK(mailbox.claim(nonce, "token", kNow + kWindow + 1).state == LoginMailbox::State::eGone);
    }

    {
        LoginMailbox mailbox(kWindow);
        bool refused = false;
        try {
            (void)mailbox.expect(challenge, "", kKey, kNow);
        } catch (const std::invalid_argument&) {
            refused = true;
        }
        CHECK(refused);
    }

    {
        LoginMailbox mailbox(kWindow);
        CHECK_THROWS((void)mailbox.expect(challenge, "token", bazarish::Bytes(1, 0), kNow));
    }

    {
        LoginMailbox mailbox(kWindow);
        const std::string first = site.issue(kNow);
        CHECK(mailbox.expect(first, "token", kKey, kNow));
        for (std::size_t i = 1; i < bazarish::service::kMaxAwaitedLogins; ++i) {
            CHECK(mailbox.expect(site.issue(kNow + 1), "token", kKey, kNow + 1));
        }
        CHECK(!mailbox.expect(site.issue(kNow + 1), "token", kKey, kNow + 1));
        CHECK(mailbox.held(bazarish::loginrelay::nonceOf(first), kNow + 1).has_value());
    }

    std::printf("TestLoginMailbox: all checks passed\n");
    return 0;
}
