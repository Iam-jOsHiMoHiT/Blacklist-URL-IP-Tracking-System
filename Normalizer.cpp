#include <iostream>
#include <string>
#include <cctype>
#include <cstdint>
using namespace std;

string cleanUrl(string url) {
    while (!url.empty() && url[0] == ' ') url.erase(0, 1);
    while (!url.empty() && url.back() == ' ') url.pop_back();

    size_t pos = url.find("://");
    if (pos != string::npos) url = url.substr(pos + 3);

    pos = url.find('#');
    if (pos != string::npos) url = url.substr(0, pos);

    size_t cut = url.find_first_of("/?");
    string host = (cut == string::npos) ? url : url.substr(0, cut);
    string rest = (cut == string::npos) ? ""  : url.substr(cut);

    pos = host.rfind('@');
    if (pos != string::npos) host = host.substr(pos + 1);

    for (size_t i = 0; i < host.size(); i++) host[i] = tolower(host[i]);

    pos = host.rfind(':');
    if (pos != string::npos) {
        string port = host.substr(pos + 1);
        if (port == "80" || port == "443") host = host.substr(0, pos);
    }

    if (host.substr(0, 4) == "www.") host = host.substr(4);

    if (!rest.empty() && rest.back() == '/') rest.pop_back();

    return host + rest;
}

bool parseIPv4(string ip, uint32_t &result) {
    result = 0;
    int parts = 0;
    string part = "";

    for (size_t i = 0; i <= ip.size(); i++) {
        if (i == ip.size() || ip[i] == '.') {
            if (part.empty() || part.size() > 3) return false;
            if (part.size() > 1 && part[0] == '0') return false;
            int value = stoi(part);
            if (value > 255) return false;
            result = (result << 8) | value;
            parts++;
            part = "";
        } else if (isdigit(ip[i])) {
            part += ip[i];
        } else {
            return false;
        }
    }
    return parts == 4;
}

    cout << "--- URL
