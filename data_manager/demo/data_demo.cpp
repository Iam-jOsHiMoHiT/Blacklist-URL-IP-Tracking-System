// data_demo.cpp — shows the Data Management module working on its own.
// Run it twice: the second run imports 0 new entries, proving the data was saved.
#include <iomanip>
#include <iostream>

#include "../src/data/FeedImporter.h"
#include "../src/data/FileStorage.h"
#include "../src/data/Normalizer.h"

int main() {
    std::cout << "=== 1. Normalizer ===\n";
    for (const std::string in : {"HTTP://www.Bank-Verify.TEST/", "http://paypal.com@evil.test/login#x",
                                 "192.0.2.10", "999.1.1.1"}) {
        InputType t = Normalizer::classify(in);
        std::cout << "  " << std::left << std::setw(38) << in << " -> "
                  << (t == InputType::INVALID ? "INVALID" : Normalizer::normalizeUrl(in)) << "\n";
    }

    std::cout << "\n=== 2. Import into storage ===\n";
    FileStorage storage("data/store");
    FeedImporter::printSummary(
        FeedImporter::importList("data/sample_blacklist.txt", "sample", storage, true),
        "sample_blacklist.txt", std::cout);
    FeedImporter::printSummary(
        FeedImporter::importList("data/urlhaus_sample.txt", "urlhaus", storage, false),
        "urlhaus_sample.txt", std::cout);

    std::cout << "\n=== 3. Blacklist now stored ===\n";
    for (const auto& e : storage.loadBlacklist())
        std::cout << "  " << std::left << std::setw(48) << e.value << std::setw(8) << e.type << e.source << "\n";

    std::cout << "\n=== 4. Logging two checks ===\n";
    CheckResult r;
    r.requestId = 1; r.normalized = "bank-verify.test"; r.verdict = Verdict::DENY; r.matchedBy = "HashTable";
    storage.logResult(r, "guest");
    r.requestId = 2; r.normalized = "example.org"; r.verdict = Verdict::ALLOW; r.matchedBy = "-";
    storage.logResult(r, "guest");

    for (const auto& h : storage.getHistory(5)) {
        const char* v = h.result.verdict == Verdict::DENY ? "DENY" : h.result.verdict == Verdict::WARN ? "WARN" : "ALLOW";
        std::cout << "  #" << h.result.requestId << "  " << std::left << std::setw(20) << h.result.normalized
                  << std::setw(6) << v << " by " << h.result.matchedBy << "\n";
    }

    std::cout << "\nRun the program again: imports show 0 new entries because the data was saved.\n";
    return 0;
}
