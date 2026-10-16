// test_storage.cpp — tests for FileStorage and FeedImporter
// Run from the project folder (it reads data/sample_blacklist.txt).
#include <cstdio>
#include <iostream>
#include <string>

#include "../src/data/FeedImporter.h"
#include "../src/data/FileStorage.h"

static int passed = 0, failed = 0;

static BlacklistEntry entry(const std::string& value, const std::string& type, const std::string& source) {
    BlacklistEntry e;
    e.value = value;
    e.type = type;
    e.source = source;
    return e;
}

// Delete the test files so every run starts clean
static void clearStore(const std::string& dir) {
    for (const char* f : {"/blacklist.txt", "/history.txt", "/users.txt", "/blacklist.txt.tmp", "/users.txt.tmp"})
        std::remove((dir + f).c_str());
}

static void check(bool ok, const std::string& name) {
    std::cout << (ok ? "  PASS  " : "  FAIL  ") << name << "\n";
    ok ? ++passed : ++failed;
}

int main() {
    const std::string dir = "test_tmp_store";
    clearStore(dir);              // start clean every run

    std::cout << "Blacklist\n";
    {
        FileStorage st(dir);
        check(st.addEntry(entry("evil.test", "DOMAIN", "admin")), "add new entry");
        check(!st.addEntry(entry("evil.test", "DOMAIN", "admin")), "duplicate is rejected");
        check(!st.addEntry(entry("", "DOMAIN", "admin")), "empty value is rejected");
        check(!st.addEntry(entry("bad|value", "URL", "admin")), "value containing '|' is rejected");
        check(st.addEntry(entry("other.test", "DOMAIN", "admin")), "add second entry");
        check(st.removeEntry("other.test"), "remove existing entry");
        check(!st.removeEntry("missing.test"), "remove missing entry returns false");
    }
    {
        FileStorage st(dir);                       // new object = program restarted
        check(st.contains("evil.test"), "entry survives restart");
        check(!st.contains("other.test"), "removed entry stays removed after restart");
        check(st.loadBlacklist().size() == 1, "exactly one entry after restart");
    }

    std::cout << "\nHistory\n";
    {
        FileStorage st(dir);
        CheckResult a;
        a.requestId = 1; a.normalized = "evil.test"; a.verdict = Verdict::DENY; a.matchedBy = "HashTable";
        CheckResult b;
        b.requestId = 2; b.normalized = "safe.test/login?pass=secret"; b.verdict = Verdict::ALLOW;
        st.logResult(a, "guest");
        st.logResult(b, "analyst1");

        auto h = st.getHistory(10);
        check(h.size() == 2, "two records saved");
        check(h[0].result.requestId == 2, "newest record comes first");
        check(h[1].result.verdict == Verdict::DENY, "verdict saved and read back");
        check(h[0].result.normalized == "safe.test/login", "query string (?pass=...) is not stored");
        check(st.getHistory(1).size() == 1, "limit works");
    }

    std::cout << "\nUsers\n";
    {
        FileStorage st(dir);
        UserRecord u;
        u.username = "admin1";
        u.salt = "salt123";
        u.hash = "hash456";
        u.role = "admin";
        check(st.saveUser(u), "save new user");
        u.failedAttempts = 2;
        check(st.saveUser(u), "update existing user");

        UserRecord got;
        check(st.getUser("admin1", got) && got.failedAttempts == 2, "updated value read back");
        check(!st.getUser("nobody", got), "unknown user not found");
    }

    std::cout << "\nFeedImporter (data/sample_blacklist.txt)\n";
    {
        clearStore(dir);
        FileStorage st(dir);
        ImportSummary s = FeedImporter::importList("data/sample_blacklist.txt", "sample", st, true);
        check(s.fileOpened, "file opened");
        check(s.imported == 6, "6 entries imported (got " + std::to_string(s.imported) + ")");
        check(s.duplicates == 1, "1 duplicate after normalization (got " + std::to_string(s.duplicates) + ")");
        check(s.invalid == 2, "2 invalid lines rejected (got " + std::to_string(s.invalid) + ")");

        BlacklistEntry found;
        for (const auto& e : st.loadBlacklist())
            if (e.value == "198.51.100.0/24") found = e;
        check(found.type == "CIDR", "IP range stored with type CIDR");

        ImportSummary again = FeedImporter::importList("data/sample_blacklist.txt", "sample", st, true);
        check(again.imported == 0, "importing twice adds nothing new");

        ImportSummary missing = FeedImporter::importList("data/no_such_file.txt", "x", st, true);
        check(!missing.fileOpened, "missing file reported, no crash");
    }

    clearStore(dir);
    std::cout << "\n" << passed << " passed, " << failed << " failed\n";
    return failed == 0 ? 0 : 1;
}
