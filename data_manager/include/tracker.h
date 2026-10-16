// tracker.h — shared types (owned by Mohit).
// This copy matches the team work plan. If Mohit's final tracker.h differs,
// use his version and adjust the few places that use CheckResult.
#pragma once
#include <string>

enum class Verdict { ALLOW, WARN, DENY };

struct CheckRequest {
    int id = 0;
    std::string raw;          // exactly as typed or generated
    std::string sourceIp;     // who sent it (rate limiter)
    std::string user;         // logged-in username, or "guest"
    int priority = 0;         // higher = processed sooner
    long long timestampMs = 0;
};

struct CheckResult {
    int requestId = 0;
    std::string normalized;   // cleaned form, e.g. "evil.com/login"
    Verdict verdict = Verdict::ALLOW;
    std::string matchedBy = "-";   // "HashTable", "DomainTrie", ...
    double lookupMicros = 0.0;     // time taken, for benchmarks
};

class Matcher {               // every lookup structure implements this
public:
    virtual ~Matcher() = default;
    virtual void insert(const std::string& key) = 0;
    virtual bool contains(const std::string& key) const = 0;
    virtual bool remove(const std::string& key) = 0;
    virtual std::string name() const = 0;
};
