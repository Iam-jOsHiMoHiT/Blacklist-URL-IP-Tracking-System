#include <iostream>
#include "but_header.hpp"

void display::showMenu()
{
    std::cout << "\n===== Blacklist URL/IP Checker =====\n";
    std::cout << "1. Check one URL/IP\n";
    std::cout << "2. Check URLs/IPs from a file\n";
    std::cout << "3. View recent history\n";
    std::cout << "4. Statistics\n";
    std::cout << "5. Add a blacklist entry\n";
    std::cout << "6. Run benchmark (hash vs linear search)\n";
    std::cout << "7. Show hash table\n";
    std::cout << "0. Exit\n";
}

void display::displayResult(const char* url, bool blocked)
{
    if (blocked)
        std::cout << "[BLOCKED] " << url << "\n";
    else
        std::cout << "[ALLOWED] " << url << "\n";
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

void display::displayStats(int entries, double loadFactor, int longestChain, int checked, int blocked)
{
    std::cout << "---- Statistics ----\n";
    std::cout << "Blacklist entries : " << entries << "\n";
    std::cout << "Load factor       : " << loadFactor << "\n";
    std::cout << "Longest chain     : " << longestChain << "\n";
    std::cout << "Checked this run  : " << checked << "\n";
    std::cout << "Blocked this run  : " << blocked << "\n";
    std::cout << "Allowed this run  : " << (checked - blocked) << "\n";
}
