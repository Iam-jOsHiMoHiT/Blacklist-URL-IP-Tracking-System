// FileStorage.cpp — Data Management module (Anirudh)
#include "FileStorage.h"

#include <cstdio>
#include <ctime>
#include <fstream>
#include <sstream>

// Folder creation without <filesystem>, so older compilers (old MinGW) also work
#ifdef _WIN32
#include <direct.h>
#define MAKE_DIR(path) _mkdir(path)
#else
#include <sys/stat.h>
#define MAKE_DIR(path) mkdir(path, 0755)
#endif

// ---------- helpers (only used in this file) ----------

static long long now() { return static_cast<long long>(std::time(nullptr)); }

static std::vector<std::string> split(const std::string& line, char sep) {
    std::vector<std::string> parts;
    std::string part;
    std::stringstream ss(line);
    while (std::getline(ss, part, sep)) parts.push_back(part);
    if (!line.empty() && line.back() == sep) parts.push_back("");   // keep a last empty field
    return parts;
}

// A field must not contain the separator or a line break, or the file would break.
static bool safeField(const std::string& s) {
    return s.find_first_of("|\r\n") == std::string::npos;
}

// For text we don't control (URLs in history): encode '|' instead of rejecting it.
static std::string escapeField(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '|') out += "%7C";
        else if (c != '\r' && c != '\n') out += c;
    }
    return out;
}

static std::string verdictToString(Verdict v) {
    switch (v) {
        case Verdict::DENY: return "DENY";
        case Verdict::WARN: return "WARN";
        default: return "ALLOW";
    }
}

static Verdict stringToVerdict(const std::string& s) {
    if (s == "DENY") return Verdict::DENY;
    if (s == "WARN") return Verdict::WARN;
    return Verdict::ALLOW;
}

// ---------- constructor ----------

FileStorage::FileStorage(const std::string& folder) {
    MAKE_DIR(folder.c_str());          // does nothing if the folder already exists
    blacklistPath = folder + "/blacklist.txt";
    historyPath = folder + "/history.txt";
    usersPath = folder + "/users.txt";
    readBlacklistFile();
}

// Write to a temporary file first, then replace the old file.
// If the program crashes while writing, the old file is still intact.
bool FileStorage::writeLinesSafely(const std::string& path, const std::vector<std::string>& lines) {
    std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) return false;
        for (const auto& l : lines) out << l << '\n';
        if (!out) return false;
    }   // file closes here (RAII)

    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        // Windows refuses to rename over an existing file: remove the old one, then rename
        std::remove(path.c_str());
        if (std::rename(tmp.c_str(), path.c_str()) != 0) return false;
    }
    return true;
}

// ---------- blacklist ----------

void FileStorage::readBlacklistFile() {
    entries.clear();
    values.clear();
    std::ifstream in(blacklistPath);
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        auto f = split(line, '|');
        if (f.size() != 4 || f[0].empty()) { ++skipped; continue; }
        try {
            BlacklistEntry e;
            e.value = f[0];
            e.type = f[1];
            e.source = f[2];
            e.addedAt = std::stoll(f[3]);
            if (values.insert(e.value).second) entries.push_back(e);
        } catch (...) {
            ++skipped;              // addedAt was not a number: corrupted line
        }
    }
}

std::vector<BlacklistEntry> FileStorage::loadBlacklist() { return entries; }

bool FileStorage::contains(const std::string& value) const { return values.count(value) > 0; }

bool FileStorage::addEntry(const BlacklistEntry& entry) {
    if (entry.value.empty() || contains(entry.value)) return false;
    if (!safeField(entry.value) || !safeField(entry.type) || !safeField(entry.source)) return false;

    BlacklistEntry e = entry;
    if (e.addedAt == 0) e.addedAt = now();

    std::ofstream out(blacklistPath, std::ios::app);   // append: fast, old lines untouched
    if (!out) return false;
    out << e.value << '|' << e.type << '|' << e.source << '|' << e.addedAt << '\n';
    if (!out) return false;

    entries.push_back(e);
    values.insert(e.value);
    return true;
}

bool FileStorage::removeEntry(const std::string& value) {
    if (!contains(value)) return false;

    std::vector<BlacklistEntry> kept;
    std::vector<std::string> lines;
    for (const auto& e : entries) {
        if (e.value == value) continue;
        kept.push_back(e);
        lines.push_back(e.value + "|" + e.type + "|" + e.source + "|" + std::to_string(e.addedAt));
    }
    if (!writeLinesSafely(blacklistPath, lines)) return false;   // memory unchanged on failure

    entries = kept;
    values.erase(value);
    return true;
}

// ---------- history ----------

void FileStorage::logResult(const CheckResult& r, const std::string& user) {
    // Privacy: never store the query string (?...) — it can contain passwords or tokens.
    std::string url = r.normalized.substr(0, r.normalized.find('?'));

    std::ofstream out(historyPath, std::ios::app);
    out << now() << '|' << escapeField(user) << '|' << r.requestId << '|' << escapeField(url) << '|'
        << verdictToString(r.verdict) << '|' << escapeField(r.matchedBy) << '|' << r.lookupMicros << '\n';
}

std::vector<HistoryRecord> FileStorage::getHistory(int limit) {
    std::vector<HistoryRecord> all;
    std::ifstream in(historyPath);
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        auto f = split(line, '|');
        if (f.size() != 7) { ++skipped; continue; }
        try {
            HistoryRecord h;
            h.time = std::stoll(f[0]);
            h.user = f[1];
            h.result.requestId = std::stoi(f[2]);
            h.result.normalized = f[3];
            h.result.verdict = stringToVerdict(f[4]);
            h.result.matchedBy = f[5];
            h.result.lookupMicros = std::stod(f[6]);
            all.push_back(h);
        } catch (...) {
            ++skipped;
        }
    }

    // newest first, at most `limit` records
    std::vector<HistoryRecord> result;
    for (auto it = all.rbegin(); it != all.rend(); ++it) {
        if (limit > 0 && static_cast<int>(result.size()) >= limit) break;
        result.push_back(*it);
    }
    return result;
}

// ---------- users ----------

std::vector<UserRecord> FileStorage::readUsersFile() {
    std::vector<UserRecord> users;
    std::ifstream in(usersPath);
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        auto f = split(line, '|');
        if (f.size() != 6) { ++skipped; continue; }
        try {
            UserRecord u;
            u.username = f[0];
            u.salt = f[1];
            u.hash = f[2];
            u.role = f[3];
            u.failedAttempts = std::stoi(f[4]);
            u.lockedUntil = std::stoll(f[5]);
            users.push_back(u);
        } catch (...) {
            ++skipped;
        }
    }
    return users;
}

bool FileStorage::getUser(const std::string& username, UserRecord& out) {
    for (const auto& u : readUsersFile()) {
        if (u.username == username) {
            out = u;
            return true;
        }
    }
    return false;
}

bool FileStorage::saveUser(const UserRecord& user) {
    if (user.username.empty() || !safeField(user.username) || !safeField(user.salt) ||
        !safeField(user.hash) || !safeField(user.role))
        return false;

    std::vector<UserRecord> users = readUsersFile();
    bool updated = false;
    for (auto& u : users) {
        if (u.username == user.username) {
            u = user;               // update existing account
            updated = true;
        }
    }
    if (!updated) users.push_back(user);

    std::vector<std::string> lines;
    for (const auto& u : users)
        lines.push_back(u.username + "|" + u.salt + "|" + u.hash + "|" + u.role + "|" +
                        std::to_string(u.failedAttempts) + "|" + std::to_string(u.lockedUntil));
    return writeLinesSafely(usersPath, lines);
}
