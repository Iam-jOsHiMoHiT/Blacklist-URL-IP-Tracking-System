#include "Normalizer.h"
#include <cctype>
using namespace std;


string Normalizer::trim(string s) {
    while (!s.empty() && s[0] == ' ') s.erase(0, 1);
    while (!s.empty() && s.back() == ' ') s.pop_back();
    return s;
}

bool Normalizer::isDigits(const string &s) {
    if (s.empty()) return false;
    for (char c : s)
        if (!isdigit((unsigned char)c)) return false;
    return true;
}

bool Normalizer::isDigitsAndDots(const string &s) {
    for (char c : s)
        if (!isdigit((unsigned char)c) && c != '.') return false;
    return true;
}

bool Normalizer::isValidHost(const string &host) {
    string h = host;

    // Separate the port, if any: "evil.com:8080"
    size_t colon = h.rfind(':');
    if (colon != string::npos) {
        if (!isDigits(h.substr(colon + 1))) return false;
        h = h.substr(0, colon);
    }

    if (h.empty()) return false;
    if (h[0] == '.' || h.back() == '.') return false;   
    if (h.find("..") != string::npos) return false;      
    if (h.find('.') == string::npos) return false;      

    for (char c : h)
        if (!isalnum((unsigned char)c) && c != '-' && c != '.') return false;

    
    if (isDigitsAndDots(h)) {
        uint32_t num;
        return parseIPv4(h, num);
    }
    return true;
}



string Normalizer::normalizeUrl(string url) {
    url = trim(url);

    size_t pos = url.find("://");                        
    if (pos != string::npos) url = url.substr(pos + 3);

    pos = url.find('#');                                 
    if (pos != string::npos) url = url.substr(0, pos);

    size_t cut = url.find_first_of("/?");                
    string host = (cut == string::npos) ? url : url.substr(0, cut);
    string rest = (cut == string::npos) ? ""  : url.substr(cut);

    pos = host.rfind('@');                               
    if (pos != string::npos) host = host.substr(pos + 1);

    for (size_t i = 0; i < host.size(); i++)              
        host[i] = tolower((unsigned char)host[i]);

    pos = host.rfind(':');                                
    if (pos != string::npos) {
        string port = host.substr(pos + 1);
        if (port == "80" || port == "443") host = host.substr(0, pos);
    }

    if (host.substr(0, 4) == "www.") host = host.substr(4);   

    if (!rest.empty() && rest.back() == '/') rest.pop_back(); 

    return host + rest;
}

bool Normalizer::parseIPv4(const string &ip, uint32_t &result) {
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
        } else if (isdigit((unsigned char)ip[i])) {
            part += ip[i];
        } else {
            return false;
        }
    }
    return parts == 4;
}

InputType Normalizer::classify(const string &input) {
    string s = trim(input);
    if (s.empty()) return InputType::INVALID;
    if (s.find(' ') != string::npos) return InputType::INVALID;   

    uint32_t num;

    
    size_t slash = s.find('/');
    if (slash != string::npos) {
        string ipPart = s.substr(0, slash);
        string bits   = s.substr(slash + 1);
        if (parseIPv4(ipPart, num) && isDigits(bits)) {
            if (bits.size() <= 2 && stoi(bits) <= 32) return InputType::CIDR;
            return InputType::INVALID;
        }
    }


    if (parseIPv4(s, num)) return InputType::IPV4;

    
    string clean = normalizeUrl(s);
    size_t cut = clean.find_first_of("/?");
    string host = (cut == string::npos) ? clean : clean.substr(0, cut);
    if (isValidHost(host)) return InputType::URL;

    return InputType::INVALID;
}

string Normalizer::typeName(InputType t) {
    switch (t) {
        case InputType::URL:  return "URL";
        case InputType::IPV4: return "IPV4";
        case InputType::CIDR: return "CIDR";
        default:              return "INVALID";
    }
}
