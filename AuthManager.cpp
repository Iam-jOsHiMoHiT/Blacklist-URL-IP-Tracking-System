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


bool AuthManager::needsCaptcha(const std::string& username) {
    UserRecord r;
    if (storage.getUser(username, r)) return r.failedAttempts > 0;
    return unknownFailures[username] > 0;
}

long long AuthManager::lockDurationFor(int failedAttempts) const {
    int rounds = failedAttempts / MAX_ATTEMPTS;
    long long seconds = BASE_LOCK_SECONDS;
    for (int i = 1; i < rounds && seconds < MAX_LOCK_SECONDS; ++i) seconds *= 2;
    return seconds < MAX_LOCK_SECONDS ? seconds : MAX_LOCK_SECONDS;
}

void AuthManager::recordFailure(UserRecord& r, LoginResult& result) {
    r.failedAttempts++;
    if (r.failedAttempts % MAX_ATTEMPTS == 0) {       
        long long seconds = lockDurationFor(r.failedAttempts);
        r.lockedUntil = clock() + seconds;
        result.status = LoginStatus::LOCKED;
        result.secondsLocked = seconds;
    }
    result.attemptsLeft = MAX_ATTEMPTS - (r.failedAttempts % MAX_ATTEMPTS);
    storage.saveUser(r);       
}

LoginResult AuthManager::login(const std::string& username, const std::string& password, bool captchaPassed) {
    LoginResult result;
    UserRecord r;

    if (!storage.getUser(username, r)) {
        PasswordHasher::hash(password, "timing-dummy");   
        unknownFailures[username]++;
        result.status = LoginStatus::INVALID_CREDENTIALS;
        return result;
    }

    long long now = clock();
    if (r.lockedUntil > now) {
        result.status = LoginStatus::LOCKED;
        result.secondsLocked = r.lockedUntil - now;
        return result;
    }

    if (r.failedAttempts > 0 && !captchaPassed) {
        result.status = LoginStatus::CAPTCHA_FAILED;
        recordFailure(r, result);                    
        return result;
    }

    if (!PasswordHasher::verify(password, r.salt, r.hash)) {
        result.status = LoginStatus::INVALID_CREDENTIALS;
        recordFailure(r, result);
        return result;
    }

    r.failedAttempts = 0;
    r.lockedUntil = 0;
    storage.saveUser(r);
    result.status = LoginStatus::SUCCESS;
    result.user = makeUser(r);
    return result;
}
