// FeedImporter.cpp — Data Management module (Anirudh)
#include "FeedImporter.h"

#include <chrono>
#include <cstdint>
#include <fstream>

#include "Normalizer.h"

ImportSummary FeedImporter::importList(const std::string& path, const std::string& source,
                                       Storage& storage, bool domainLevel) {
    ImportSummary s;
    auto start = std::chrono::steady_clock::now();

    std::ifstream in(path);
    if (!in) return s;                 // fileOpened stays false
    s.fileOpened = true;

    std::string line;
    bool firstLine = true;
    while (std::getline(in, line)) {
        // Files saved on Windows can start with an invisible "BOM" marker: remove it
        if (firstLine && line.rfind("\xEF\xBB\xBF", 0) == 0) line.erase(0, 3);
        firstLine = false;
        ++s.read;

        // 1. Skip empty lines and comments
        size_t p = line.find_first_not_of(" \t\r");
        if (p == std::string::npos || line[p] == '#') {
            ++s.skipped;
            continue;
        }

        // 2. Classify; invalid lines never reach the blacklist
        InputType t = Normalizer::classify(line);
        if (t == InputType::INVALID) {
            ++s.invalid;
            continue;
        }

        // 3. Normalize and decide the entry type
        BlacklistEntry e;
        e.source = source;
        e.value = Normalizer::normalizeUrl(line);

        uint32_t ip;
        if (t == InputType::CIDR) {
            e.type = "CIDR";
        } else if (Normalizer::parseIPv4(e.value, ip)) {
            e.type = "IPV4";           // also catches "http://1.2.3.4/" -> "1.2.3.4"
        } else {
            bool hasPath = e.value.find_first_of("/?") != std::string::npos;
            e.type = (hasPath || !domainLevel) ? "URL" : "DOMAIN";
        }

        // 4. Save, counting duplicates
        if (storage.contains(e.value)) {
            ++s.duplicates;
        } else if (storage.addEntry(e)) {
            ++s.imported;
        } else {
            ++s.failed;
        }
    }

    auto end = std::chrono::steady_clock::now();
    s.millis = std::chrono::duration<double, std::milli>(end - start).count();
    return s;
}

void FeedImporter::printSummary(const ImportSummary& s, const std::string& label, std::ostream& out) {
    out << "Import: " << label << "\n";
    if (!s.fileOpened) {
        out << "  ERROR: file could not be opened\n";
        return;
    }
    out << "  lines read : " << s.read << "\n"
        << "  imported   : " << s.imported << "\n"
        << "  duplicates : " << s.duplicates << "\n"
        << "  invalid    : " << s.invalid << "\n"
        << "  skipped    : " << s.skipped << " (comments / empty)\n";
    if (s.failed > 0) out << "  failed     : " << s.failed << "\n";
    out << "  time       : " << s.millis << " ms\n";
}
