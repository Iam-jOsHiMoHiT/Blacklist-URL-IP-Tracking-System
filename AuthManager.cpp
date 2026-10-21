// AuthManager.cpp — Authentication module (Manav)
#include "AuthManager.h"

#include <cctype>
#include <ctime>

#include "PasswordHasher.h"

const int AuthManager::MAX_ATTEMPTS = 3;
const long long AuthManager::BASE_LOCK_SECONDS = 30;
const long long AuthManager::MAX_LOCK_SECONDS = 3600;

AuthManager::AuthManager(Storage& storage) : storage(storage) {
    clock = [] { return static_cast<long long>(std::time(nullptr)); };
}

void AuthManager::setClock(std::function<long long()> c) { clock = c; }

// ---------- accounts ----------

bool AuthManager::isStrongEnough(const std::string& username, const std::string& password) {
    if (password.size() < 8 || password == username) return false;
    bool letter = false, digit = false;
    for (char c : password) {
        if (std::isalpha(static_cast<unsigned char>(c))) letter = true;
        if (std::isdigit(static_cast<unsigned char>(c))) digit = true;
    }
    return letter && digit;
}

bool AuthManager::createFirstAdmin(const std::string& username, const std::string& password) {
    UserRecord existing;
    if (username.empty() || storage.getUser(username, existing)) return false;
    if (!isStrongEnough(username, password)) return false;

    UserRecord r;
    r.username = username;
    r.salt = PasswordHasher::generateSalt();
    r.hash = PasswordHasher::hash(password, r.salt);
    r.role = "admin";
    return storage.saveUser(r);
}

bool AuthManager::registerUser(const User& by, const std::string& username,
                               const std::string& password, const std::string& role) {
    if (!by.canManageUsers()) return false;                    // only admins
    if (role != "admin" && role != "analyst") return false;

    UserRecord existing;
    if (username.empty() || storage.getUser(username, existing)) return false;
    if (!isStrongEnough(username, password)) return false;

    UserRecord r;
    r.username = username;
    r.salt = PasswordHasher::generateSalt();
    r.hash = PasswordHasher::hash(password, r.salt);
    r.role = role;
    return storage.saveUser(r);
}

std::unique_ptr<User> AuthManager::makeUser(const UserRecord& r) {
    if (r.role == "admin") return std::unique_ptr<User>(new Admin(r.username));
    return std::unique_ptr<User>(new Analyst(r.username));
}

// ---------- login ----------

bool AuthManager::needsCaptcha(const std::string& username) {
    UserRecord r;
    if (storage.getUser(username, r)) return r.failedAttempts > 0;
    // Unknown usernames behave the same way, so an attacker can't tell which names exist
    return unknownFailures[username] > 0;
}

// 3 failures -> 30 s, 6 -> 60 s, 9 -> 120 s ... doubling, up to 1 hour
long long AuthManager::lockDurationFor(int failedAttempts) const {
    int rounds = failedAttempts / MAX_ATTEMPTS;
    long long seconds = BASE_LOCK_SECONDS;
    for (int i = 1; i < rounds && seconds < MAX_LOCK_SECONDS; ++i) seconds *= 2;
    return seconds < MAX_LOCK_SECONDS ? seconds : MAX_LOCK_SECONDS;
}

void AuthManager::recordFailure(UserRecord& r, LoginResult& result) {
    r.failedAttempts++;
    if (r.failedAttempts % MAX_ATTEMPTS == 0) {          // every 3rd failure: lock
        long long seconds = lockDurationFor(r.failedAttempts);
        r.lockedUntil = clock() + seconds;
        result.status = LoginStatus::LOCKED;
        result.secondsLocked = seconds;
    }
    result.attemptsLeft = MAX_ATTEMPTS - (r.failedAttempts % MAX_ATTEMPTS);
    storage.saveUser(r);                                  // survives restart
}

LoginResult AuthManager::login(const std::string& username, const std::string& password, bool captchaPassed) {
    LoginResult result;
    UserRecord r;

    // Unknown user: same answer as a wrong password, so usernames can't be discovered
    if (!storage.getUser(username, r)) {
        PasswordHasher::hash(password, "timing-dummy");   // take the same time as a real check
        unknownFailures[username]++;
        result.status = LoginStatus::INVALID_CREDENTIALS;
        return result;
    }

    // 1. Locked? Refuse without even checking the password
    long long now = clock();
    if (r.lockedUntil > now) {
        result.status = LoginStatus::LOCKED;
        result.secondsLocked = r.lockedUntil - now;
        return result;
    }

    // 2. After a failure, a human check is required
    if (r.failedAttempts > 0 && !captchaPassed) {
        result.status = LoginStatus::CAPTCHA_FAILED;
        recordFailure(r, result);                        // a failed CAPTCHA counts as a failed try
        return result;
    }

    // 3. Check the password
    if (!PasswordHasher::verify(password, r.salt, r.hash)) {
        result.status = LoginStatus::INVALID_CREDENTIALS;
        recordFailure(r, result);
        return result;
    }

    // 4. Success: reset the counters
    r.failedAttempts = 0;
    r.lockedUntil = 0;
    storage.saveUser(r);
    result.status = LoginStatus::SUCCESS;
    result.user = makeUser(r);
    return result;
}
