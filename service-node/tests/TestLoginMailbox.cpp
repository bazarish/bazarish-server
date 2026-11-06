// Bazarish project (c) 2026
#include "LoginMailbox.hpp"

#include <LoginRelay.hpp>

#include <bazarish/LoginChallenge.hpp>

#include <cstdio>
#include <cstdlib>
#include <string>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

namespace {

using bazarish::service::LoginMailbox;

constexpr std::int64_t kNow = 1800000000;
constexpr std::int64_t kWindow = 300;

}  // namespace

int main()
{
    bazarish::service::LoginChallenge site("site-secret",
        bazarish::service::LoginConsumer{"Bazarish server", {"https://portal.example"}, "Account owner"});
    const std::string challenge = site.issue(kNow);
    const std::string other = site.issue(kNow);
    const std::string nonce = bazarish::loginrelay::nonceOf(challenge);

    {
        LoginMailbox mailbox(kWindow);
        CHECK(mailbox.challengeOf(nonce, kNow).empty());
        CHECK(!mailbox.deliver(nonce, challenge, "blob", kNow));
        mailbox.expect(challenge, "token", kNow);
        CHECK(mailbox.challengeOf(nonce, kNow) == challenge);
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
        mailbox.expect(challenge, "token", kNow);
        CHECK(mailbox.claim(nonce, "token", kNow + kWindow).state == LoginMailbox::State::eWaiting);
        CHECK(mailbox.challengeOf(nonce, kNow + kWindow + 1).empty());
        CHECK(!mailbox.deliver(nonce, challenge, "blob", kNow + kWindow + 1));
        CHECK(mailbox.claim(nonce, "token", kNow + kWindow + 1).state == LoginMailbox::State::eGone);
    }

    {
        LoginMailbox mailbox(kWindow);
        bool refused = false;
        try {
            mailbox.expect(challenge, "", kNow);
        } catch (const std::invalid_argument&) {
            refused = true;
        }
        CHECK(refused);
    }

    {
        LoginMailbox mailbox(kWindow);
        const std::string first = site.issue(kNow);
        mailbox.expect(first, "token", kNow);
        for (std::size_t i = 0; i < bazarish::service::kMaxAwaitedLogins; ++i) {
            mailbox.expect(site.issue(kNow + 1), "token", kNow + 1);
        }
        CHECK(mailbox.challengeOf(bazarish::loginrelay::nonceOf(first), kNow + 1).empty());
    }

    std::printf("TestLoginMailbox: all checks passed\n");
    return 0;
}
