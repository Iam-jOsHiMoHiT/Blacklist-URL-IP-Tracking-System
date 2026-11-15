#include <iostream>
#include "but_header.hpp"

void display::showMenu()
{
    std::cout << "\n===== Blacklist URL/IP Checker =====\n";
    std::cout << "1. Check one URL/IP\n";
    std::cout << "2. Check URLs/IPs from a file\n";
    std::cout << "3. View recent history\n";
    std::cout << "4. Statistics\n";
    std::cout << "5. Add a blacklist entry (Admin only)\n";
    std::cout << "6. Run benchmark (hash vs linear search)\n";
    std::cout << "7. Show hash table\n";
    std::cout << "8. Register a new user (Admin only)\n";
    std::cout << "0. Exit\n";
}

void display::displayResult(const char* url, bool blocked, const char* reason, double mlSpam)
{
    if (blocked)
        std::cout << "[BLOCKED] " << url;
    else
        std::cout << "[ALLOWED] " << url;

    if (reason != NULL && reason[0] != '\0')
        std::cout << "  (" << reason << ")";
    std::cout << "\n";

    if (mlSpam >= 0) {
        std::cout << "          ML spam probability: " << (int)(mlSpam * 100 + 0.5) << "%";
        if (mlSpam >= ML_WARN_THRESHOLD)
            std::cout << "  <-- WARNING: ML model finds this URL suspicious (advisory)";
        std::cout << "\n";
    }
}

void display::displayInvalid(const char* input)
{
    std::cout << "[INVALID] " << input << "  (not a valid URL or IPv4 address)\n";
}

void display::displayHistory(char lines[][MAX_LINE], int count)
{
    if (count <= 0) {
        std::cout << "No history yet.\n";
        return;
    }

    std::cout << "---- Last " << count << " checks (oldest first) ----\n";
    for (int i = 0; i < count; i++)
        std::cout << lines[i] << "\n";
}

void display::displayStats(int entries, int cidrCount, double loadFactor, int longestChain,
                           int checked, int blocked, int cacheHits, int bloomSkips,
                           int mlScored, int mlFlagged)
{
    std::cout << "---- Statistics ----\n";
    std::cout << "Blacklist entries : " << entries << "\n";
    std::cout << "CIDR ranges       : " << cidrCount << "\n";
    std::cout << "Load factor       : " << loadFactor << "\n";
    std::cout << "Longest chain     : " << longestChain << "\n";
    std::cout << "Checked this run  : " << checked << "\n";
    std::cout << "Blocked this run  : " << blocked << "\n";
    std::cout << "Allowed this run  : " << (checked - blocked) << "\n";
    std::cout << "Cache hits        : " << cacheHits << "\n";
    std::cout << "Bloom filter skips: " << bloomSkips << "\n";
    std::cout << "ML scored URLs    : " << mlScored << "\n";
    std::cout << "ML warnings       : " << mlFlagged << "\n";
}
