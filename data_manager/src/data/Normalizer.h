// Normalizer.h — Data Management module (Anirudh)
// Converts every URL / IP into one standard form before it is checked,
// so formatting tricks cannot bypass the blacklist.
#pragma once
#include <cstdint>
#include <string>

enum class InputType { URL, IPV4, CIDR, INVALID };

class Normalizer {
public:
    // "HTTP://www.Evil.COM:80/a/#top"  ->  "evil.com/a"
    static std::string normalizeUrl(const std::string& raw);

    // "192.168.1.1" -> true, out = one 32-bit number. Rejects 256.1.1.1, 01.2.3.4, 1.2.3
    static bool parseIPv4(const std::string& s, uint32_t& out);

    // Decides what kind of input this is. INVALID input must never reach the matchers.
    static InputType classify(const std::string& raw);

private:
    static std::string trim(const std::string& s);
    static std::string toLower(std::string s);
    static bool isDigits(const std::string& s);
    static bool isValidHost(const std::string& host);
};
