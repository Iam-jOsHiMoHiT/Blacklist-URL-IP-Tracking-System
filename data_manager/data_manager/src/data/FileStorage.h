// FileStorage.h — Data Management module (Anirudh)
// Stores data in three text files, one record per line, fields separated by '|':
//   blacklist.txt   value|type|source|addedAt
//   history.txt     time|user|requestId|normalized|verdict|matchedBy|micros
//   users.txt       username|salt|hash|role|failedAttempts|lockedUntil
#pragma once
#include <string>
#include <unordered_set>
#include <vector>

#include "Storage.h"

class FileStorage : public Storage {
public:
    explicit FileStorage(const std::string& folder);   // creates the folder if needed

    std::vector<BlacklistEntry> loadBlacklist() override;
    bool addEntry(const BlacklistEntry& entry) override;
    bool removeEntry(const std::string& value) override;
    bool contains(const std::string& value) const override;

    void logResult(const CheckResult& result, const std::string& user) override;
    std::vector<HistoryRecord> getHistory(int limit) override;

    bool getUser(const std::string& username, UserRecord& out) override;
    bool saveUser(const UserRecord& user) override;

    int skippedLines() const { return skipped; }      // corrupted lines found while reading

private:
    std::string blacklistPath, historyPath, usersPath;
    std::vector<BlacklistEntry> entries;              // blacklist kept in memory
    std::unordered_set<std::string> values;           // O(1) duplicate check
    int skipped = 0;

    void readBlacklistFile();
    std::vector<UserRecord> readUsersFile();
    static bool writeLinesSafely(const std::string& path, const std::vector<std::string>& lines);
};
