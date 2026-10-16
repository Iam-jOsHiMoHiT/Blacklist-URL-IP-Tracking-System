// Normalizer.cpp — Data Management module (Anirudh)
#include "Normalizer.h"

#include <cctype>

// ---------- small helpers ----------

std::string Normalizer::trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";          // only spaces
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::string Normalizer::toLower(std::string s) {
    // cast to unsigned char first: std::tolower on a negative char is undefined behaviour
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool Normalizer::isDigits(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s)
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    return true;
}

// A host is valid if: not empty, has a dot, only letters/digits/hyphens/dots,
// and no empty labels ("evil..com", ".evil.com", "evil.com.").
bool Normalizer::isValidHost(const std::string& host) {
    if (host.empty() || host.size() > 253) return false;
    if (host.find('.') == std::string::npos) return false;
    if (host.front() == '.' || host.back() == '.') return false;
    if (host.find("..") != std::string::npos) return false;
    for (char c : host) {
        bool ok = std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '.';
        if (!ok) return false;
    }
    return true;
}

// ---------- IPv4 ----------

bool Normalizer::parseIPv4(const std::string& s, uint32_t& out) {
    uint32_t result = 0;
    int parts = 0;
    size_t start = 0;

    while (true) {
        size_t dot = s.find('.', start);
        std::string part = s.substr(start, dot == std::string::npos ? std::string::npos : dot - start);

        if (!isDigits(part) || part.size() > 3) return false;   // empty, letters, or too long
        if (part.size() > 1 && part[0] == '0') return false;   // "01": could be read as octal, so reject
        int value = std::stoi(part);                            // safe: only digits, max 3 of them
        if (value > 255) return false;

        result = (result << 8) | static_cast<uint32_t>(value);  // append 8 bits
        if (++parts > 4) return false;

        if (dot == std::string::npos) break;
        start = dot + 1;
    }

    if (parts != 4) return false;
    out = result;
    return true;
}

// ---------- URL ----------

std::string Normalizer::normalizeUrl(const std::string& raw) {
    // Step 1: trim spaces
    std::string s = trim(raw);
    if (s.empty()) return "";

    // Step 2: remove the scheme ("http://", "https://", any case)
    size_t pos = s.find("://");
    if (pos != std::string::npos) s = s.substr(pos + 3);

    // Step 3: remove the fragment (#...) — it never reaches the server
    pos = s.find('#');
    if (pos != std::string::npos) s.erase(pos);

    // Step 4: split into authority (host[:port]) and rest (path + query)
    size_t cut = s.find_first_of("/?");
    std::string authority = (cut == std::string::npos) ? s : s.substr(0, cut);
    std::string rest = (cut == std::string::npos) ? "" : s.substr(cut);

    // Step 5: drop "user@" — in paypal.com@evil.com the real site is evil.com
    pos = authority.rfind('@');
    if (pos != std::string::npos) authority = authority.substr(pos + 1);

    // Step 6: lower-case the host only (paths are case-sensitive)
    authority = toLower(authority);

    // Step 7: remove default ports :80 and :443; keep others like :8080
    pos = authority.rfind(':');
    if (pos != std::string::npos) {
        std::string port = authority.substr(pos + 1);
        if (port == "80" || port == "443") authority.erase(pos);
    }

    // Step 8: strip "www." (team decision)
    if (authority.rfind("www.", 0) == 0) authority.erase(0, 4);

    // Step 9: remove trailing "/" from the path, keep the query (?...)
    size_t q = rest.find('?');
    std::string path = rest.substr(0, q);
    std::string query = (q == std::string::npos) ? "" : rest.substr(q);
    while (!path.empty() && path.back() == '/') path.pop_back();

    // Step 10: reassemble
    return authority + path + query;
}

// ---------- classify ----------

InputType Normalizer::classify(const std::string& raw) {
    std::string s = trim(raw);
    if (s.empty()) return InputType::INVALID;

    uint32_t ip;

    // CIDR range: "a.b.c.d/n" with n from 0 to 32
    size_t slash = s.find('/');
    if (slash != std::string::npos && s.find("://") == std::string::npos) {
        std::string left = s.substr(0, slash);
        std::string right = s.substr(slash + 1);
        if (parseIPv4(left, ip)) {
            if (!isDigits(right) || right.size() > 2) return InputType::INVALID;
            return std::stoi(right) <= 32 ? InputType::CIDR : InputType::INVALID;
        }
    }

    // Plain IPv4 address
    if (parseIPv4(s, ip)) return InputType::IPV4;

    // Otherwise treat it as a URL: normalize, then check the host
    std::string norm = normalizeUrl(s);
    std::string host = norm.substr(0, norm.find_first_of("/?"));

    size_t colon = host.find(':');
    if (colon != std::string::npos) {
        if (!isDigits(host.substr(colon + 1))) return InputType::INVALID;   // bad port
        host = host.substr(0, colon);
    }

    // Host made only of digits and dots must be a real IPv4 (rejects 999.1.1.1)
    if (host.find_first_not_of("0123456789.") == std::string::npos)
        return parseIPv4(host, ip) ? InputType::URL : InputType::INVALID;

    return isValidHost(host) ? InputType::URL : InputType::INVALID;
}
