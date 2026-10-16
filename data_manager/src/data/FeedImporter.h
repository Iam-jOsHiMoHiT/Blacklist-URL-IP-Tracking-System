// FeedImporter.h — Data Management module (Anirudh)
// Imports plain-text lists (one URL / domain / IP per line), e.g. the URLhaus
// plain-text dump, the OpenPhish feed, or our own sample file.
#pragma once
#include <ostream>
#include <string>

#include "Storage.h"

struct ImportSummary {
    bool fileOpened = false;
    int read = 0;          // every line in the file
    int imported = 0;      // new entries saved
    int duplicates = 0;    // already in the blacklist
    int invalid = 0;       // rejected by the Normalizer
    int skipped = 0;       // comments (#) and empty lines
    int failed = 0;        // could not be saved
    double millis = 0.0;   // time taken
};

class FeedImporter {
public:
    // domainLevel = true  -> bare hosts become "DOMAIN" entries (block all subdomains)
    //                        use for our sample file and admin lists
    // domainLevel = false -> bare hosts stay exact "URL" entries
    //                        use for threat feeds, which often list hacked pages on genuine sites
    static ImportSummary importList(const std::string& path, const std::string& source,
                                    Storage& storage, bool domainLevel);

    static void printSummary(const ImportSummary& s, const std::string& label, std::ostream& out);
};
