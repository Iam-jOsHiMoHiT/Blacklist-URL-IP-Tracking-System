#include "but_header.hpp"
#include <fstream>
#include <iostream>

data::data()
{
    blacklistFile = "blacklist.txt";
    historyFile = "history.txt";
}

bool data::loadBlacklist(hashTable& table)
{
    std::ifstream in(blacklistFile);

    if (!in.is_open())
    {
        std::cerr << "[data] Could not open " << blacklistFile << "\n";
        return false;
    }

    std::string url;
    while (std::getline(in, url))
    {
        if (url.empty()) continue;   // skip blank lines
        table.insert(url);           // hand each entry to the hash table
    }

    in.close();
    return true;
}

bool data::saveResult(std::string url, bool blocked)
{
    std::ofstream out(historyFile, std::ios::app);   // append, never overwrite

    if (!out.is_open())
    {
        std::cerr << "[data] Could not open " << historyFile << "\n";
        return false;
    }

    out << url << " " << (blocked ? "BLOCKED" : "ALLOWED") << "\n";
    out.close();
    return true;
}

std::vector<std::string> data::getHistory()
{
    std::vector<std::string> history;
    std::ifstream in(historyFile);

    if (!in.is_open())
    {
        return history;   // empty vector if no history yet — not an error
    }

    std::string line;
    while (std::getline(in, line))
    {
        if (line.empty()) continue;
        history.push_back(line);
    }

    in.close();
    return history;
}
