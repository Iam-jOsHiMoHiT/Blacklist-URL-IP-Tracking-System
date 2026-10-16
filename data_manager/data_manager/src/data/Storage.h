// Storage.h — Data Management module (Anirudh)
// Abstract class: the rest of the program only talks to Storage, so we can
// switch from FileStorage to SqliteStorage later without changing other code.
#pragma once
#include <string>
#include <vector>

#include "tracker.h"

// One blacklist entry.
// type: "URL"    exact match only (feed URLs; often hacked pages on genuine sites)
//       "DOMAIN" whole domain + subdomains (goes to the domain trie)
//       "IPV4"   single IP address
//       "CIDR"   IP range, e.g. 198.51.100.0/24
struct BlacklistEntry {
    std::string value;
    std::string type;
    std::string source;       // "sample", "urlhaus", "admin", ...
    long long addedAt = 0;    // seconds since 1970 (0 = now)
};

// One line of check history.
struct HistoryRecord {
    long long time = 0;
    std::string user;
    CheckResult result;
};

// One user account (used by Manav's AuthManager).
struct UserRecord {
    std::string username;
    std::string salt;
    std::string hash;
    std::string role;              // "admin" or "analyst"
    int failedAttempts = 0;
    long long lockedUntil = 0;     // seconds since 1970; 0 = not locked
};

class Storage {
public:
    virtual ~Storage() = default;

    // Blacklist
    virtual std::vector<BlacklistEntry> loadBlacklist() = 0;
    virtual bool addEntry(const BlacklistEntry& entry) = 0;      // false if duplicate or invalid
    virtual bool removeEntry(const std::string& value) = 0;      // false if not found
    virtual bool contains(const std::string& value) const = 0;

    // History
    virtual void logResult(const CheckResult& result, const std::string& user) = 0;
    virtual std::vector<HistoryRecord> getHistory(int limit) = 0; // newest first; limit <= 0 = all

    // Users
    virtual bool getUser(const std::string& username, UserRecord& out) = 0;
    virtual bool saveUser(const UserRecord& user) = 0;           // add or update
};
