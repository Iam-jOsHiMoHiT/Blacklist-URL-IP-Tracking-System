#ifndef NORMALIZER_H
#define NORMALIZER_H

#include <string>
#include <cstdint>

enum class InputType { URL, IPV4, CIDR, INVALID };

class Normalizer {
public:
    static std::string normalizeUrl(std::string url);
    static bool parseIPv4(const std::string &ip, uint32_t &result);
    static InputType classify(const std::string &input);
    static std::string typeName(InputType t);

private:
    static std::string trim(std::string s);
    static bool isDigits(const std::string &s);
    static bool isDigitsAndDots(const std::string &s);
    static bool isValidHost(const std::string &host);
};

#endif
