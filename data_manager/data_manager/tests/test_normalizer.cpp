// test_normalizer.cpp — run this live in the Phase 2 demo
#include <iostream>
#include <string>

#include "../src/data/Normalizer.h"

static int passed = 0, failed = 0;

static void check(bool ok, const std::string& name) {
    std::cout << (ok ? "  PASS  " : "  FAIL  ") << name << "\n";
    ok ? ++passed : ++failed;
}

static void url(const std::string& in, const std::string& expected) {
    std::string got = Normalizer::normalizeUrl(in);
    check(got == expected, "\"" + in + "\" -> \"" + got + "\"" +
                               (got == expected ? "" : "  (expected \"" + expected + "\")"));
}

static const char* name(InputType t) {
    switch (t) {
        case InputType::URL: return "URL";
        case InputType::IPV4: return "IPV4";
        case InputType::CIDR: return "CIDR";
        default: return "INVALID";
    }
}

static void type(const std::string& in, InputType expected) {
    InputType got = Normalizer::classify(in);
    check(got == expected, "classify(\"" + in + "\") = " + name(got));
}

int main() {
    std::cout << "normalizeUrl\n";
    url("HTTP://Evil.COM/", "evil.com");
    url("https://www.evil.com", "evil.com");
    url("http://evil.com:80", "evil.com");
    url("https://evil.com:8080/x", "evil.com:8080/x");
    url("https://evil.com/Login#top", "evil.com/Login");
    url("  evil.com/a/  ", "evil.com/a");
    url("http://paypal.com@evil.com", "evil.com");
    url("evil.com/a/?id=5", "evil.com/a?id=5");

    std::cout << "\nclassify\n";
    type("192.168.1.1", InputType::IPV4);
    type("256.1.1.1", InputType::INVALID);
    type("999.1.1.1", InputType::INVALID);
    type("01.2.3.4", InputType::INVALID);
    type("10.0.0.0/8", InputType::CIDR);
    type("10.0.0.0/33", InputType::INVALID);
    type("", InputType::INVALID);
    type("   ", InputType::INVALID);
    type("HTTP://Bank-Verify.TEST/", InputType::URL);
    type("evil..com", InputType::INVALID);
    type("http://1.2.3.4/payload.exe", InputType::URL);

    std::cout << "\n" << passed << " passed, " << failed << " failed\n";
    return failed == 0 ? 0 : 1;
}
