// Bazarish project (c) 2026
#include "PushQueue.hpp"

#include <bazarish/Address.hpp>
#include <bazarish/ConfigFile.hpp>
#include <bazarish/PrivateFile.hpp>

#include <nlohmann/json.hpp>

#include <array>
#include <optional>
#include <stdexcept>
#include <utility>

namespace bazarish::service {

namespace fs = std::filesystem;

namespace {

constexpr char kUnsentDirectory[] = "unsent";
constexpr char kRecordSuffix[] = ".json";
constexpr std::array<const char*, 4> kMarks = {"quota", "card", "addressDown", "forget"};

void settle(const PushOutcome outcome, bool& unsent, bool& delivered, bool& unreachable)
{
    switch (outcome) {
    case PushOutcome::eDelivered:
        unsent = false;
        delivered = true;
        return;
    case PushOutcome::eUnreachable:
        unreachable = true;
        return;
    case PushOutcome::eRefused:
        return;
    }
}

}  // namespace

PushQueue::PushQueue(
    const fs::path& root, SubscriptionStore& store, UserLocks& locks, Delivery delivery)
    : root_(root / kUnsentDirectory)
    , store_(store)
    , locks_(locks)
    , delivery_(std::move(delivery))
{
    if (!delivery_.quota || !delivery_.card || !delivery_.takeDownAddress || !delivery_.forget) {
        throw std::invalid_argument("the server service tells its messaging server of every quota, card,"
                                    " address taken down and account deleted");
    }
    fs::create_directories(root_);
    for (const std::string& user : unsentUsers()) {
        (void)unsent(user);
    }
    worker_ = std::thread([this]() { run(); });
}

PushQueue::~PushQueue()
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        stopping_ = true;
    }
    wake_.notify_all();
    worker_.join();
}

fs::path PushQueue::unsentPath(const std::string& user) const
{
    requireFingerprint(user);
    return root_ / (user + kRecordSuffix);
}

void PushQueue::record(const std::string& user, const Unsent changed)
{
    Unsent merged = unsent(user);
    merged.quota = merged.quota || changed.quota;
    merged.card = merged.card || changed.card;
    merged.addressDown = merged.addressDown || changed.addressDown;
    merged.forget = merged.forget || changed.forget;
    write(user, merged);
}

void PushQueue::settled(const std::string& user, const Unsent confirmed)
{
    Unsent left = unsent(user);
    left.quota = left.quota && !confirmed.quota;
    left.card = left.card && !confirmed.card;
    left.addressDown = left.addressDown && !confirmed.addressDown;
    left.forget = left.forget && !confirmed.forget;
    write(user, left);
}

PushQueue::Unsent PushQueue::unsent(const std::string& user) const
{
    const fs::path path = unsentPath(user);
    if (!fs::exists(path)) {
        return {};
    }
    const nlohmann::json body = readJsonFile(path);
    for (const char* const mark : kMarks) {
        if (!body.is_object() || !body.contains(mark) || !body.at(mark).is_boolean()) {
            throw std::runtime_error(path.string()
                + " is not an unsent mark this server service reads: it names quota, card, addressDown"
                  " and forget as true or false");
        }
    }
    return {body.at("quota").get<bool>(), body.at("card").get<bool>(),
        body.at("addressDown").get<bool>(), body.at("forget").get<bool>()};
}

void PushQueue::write(const std::string& user, const Unsent left)
{
    const fs::path path = unsentPath(user);
    if (!left.any()) {
        fs::remove(path);
        return;
    }
    writeFileAtomic(path,
        nlohmann::json{
            {"quota", left.quota}, {"card", left.card}, {"addressDown", left.addressDown},
            {"forget", left.forget}}
            .dump());
}

std::vector<std::string> PushQueue::unsentUsers() const
{
    std::vector<std::string> users;
    for (const fs::directory_entry& entry : fs::directory_iterator(root_)) {
        if (entry.is_regular_file() && entry.path().extension() == kRecordSuffix) {
            users.push_back(entry.path().stem().string());
        }
    }
    return users;
}

PushQueue::Attempt PushQueue::attempt(const std::string& user)
{
    Attempt result{unsent(user)};
    if (!result.left.any()) {
        return result;
    }
    if (result.left.forget) {
        settle(delivery_.forget(user), result.left.forget, result.delivered, result.unreachable);
        if (!result.left.forget) {
            result.left.addressDown = false;
        }
    }
    if (result.left.addressDown && !result.unreachable && !result.left.forget) {
        settle(delivery_.takeDownAddress(user), result.left.addressDown, result.delivered,
            result.unreachable);
    }
    const std::optional<SubscriptionStore::Account> account = store_.getAccount(user);
    if (!account.has_value()) {
        result.left.quota = false;
        result.left.card = false;
    }
    if (result.left.quota && !result.unreachable && !result.left.forget) {
        settle(delivery_.quota(user, account->quotaBytes), result.left.quota, result.delivered,
            result.unreachable);
    }
    if (result.left.card && !result.unreachable && !result.left.forget) {
        settle(delivery_.card(user), result.left.card, result.delivered, result.unreachable);
    }
    write(user, result.left);
    return result;
}

PushQueue::Unsent PushQueue::deliver(const std::string& user)
{
    const Attempt done = attempt(user);
    if (done.delivered) {
        serverReached();
    }
    return done.left;
}

void PushQueue::serverReached()
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        reached_ = true;
    }
    wake_.notify_one();
}

void PushQueue::drain()
{
    for (const std::string& user : unsentUsers()) {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_) {
                return;
            }
        }
        const UserLocks::Held held = locks_.hold(user);
        if (attempt(user).unreachable) {
            return;
        }
    }
}

void PushQueue::run()
{
    std::unique_lock<std::mutex> lock(mutex_);
    while (true) {
        wake_.wait(lock, [this]() { return reached_ || stopping_; });
        if (stopping_) {
            return;
        }
        reached_ = false;
        lock.unlock();
        drain();
        lock.lock();
    }
}

}  // namespace bazarish::service
