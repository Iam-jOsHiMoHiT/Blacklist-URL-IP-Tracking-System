#include "but_header.hpp"
#include <fstream>
#include <iostream>
using namespace std;

data::data()
{
    blacklistFile = "blacklist.txt";
    historyFile = "history.txt";
}


bool data::loadBlacklist(hashTable& table)
{
    ifstream in(blacklistFile);

    if (!in.is_open())
    {
        cerr << "[data] Could not open " << blacklistFile << "\n";
        return false;
    }

    string url;
    while (getline(in, url))
    {
        if (url.empty()) continue;   
        table.insert(url);          
    }

    in.close();
    return true;
}


bool data::saveResult(string url, bool blocked)
{
    ofstream out(historyFile, ios::app);   

    if (!out.is_open())
    {
        cerr << "[data] Could not open " << historyFile << "\n";
        return false;
    }

    out << url << " " << (blocked ? "BLOCKED" : "ALLOWED") << "\n";
    out.close();
    return true;
}

vector<string> data::getHistory()
{
    vector<string> history;
    ifstream in(historyFile);

    if (!in.is_open())
    {
        return history;   
    }

    string line;
    while (getline(in, line))
    {
        if (line.empty()) continue;
        history.push_back(line);
    }

    in.close();
    return history;
}
