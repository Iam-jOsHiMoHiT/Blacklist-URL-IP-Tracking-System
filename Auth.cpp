#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <vector>
#include "Auth.hpp"

using namespace std;

long long nowMs() {
    return chrono::duration_cast<chrono::milliseconds>(
               chrono::system_clock::now().time_since_epoch()).count();
}

class SHA256 {
    static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

public:
    static string hash(const string& s) {
        static const uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
        uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

        vector<uint8_t> msg(s.begin(), s.end());
        uint64_t bitLen = (uint64_t)s.size() * 8;
        msg.push_back(0x80);
        while (msg.size() % 64 != 56) msg.push_back(0);
        for (int i = 7; i >= 0; --i) msg.push_back((uint8_t)((bitLen >> (i * 8)) & 0xff));

        for (size_t off = 0; off < msg.size(); off += 64) {
            uint32_t w[64];
            for (int i = 0; i < 16; ++i)
                w[i] = ((uint32_t)msg[off + 4 * i] << 24) | ((uint32_t)msg[off + 4 * i + 1] << 16) |
                       ((uint32_t)msg[off + 4 * i + 2] << 8) | (uint32_t)msg[off + 4 * i + 3];
            for (int i = 16; i < 64; ++i) {
                uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
                uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }
            uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
            for (int i = 0; i < 64; ++i) {
                uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                uint32_t ch = (e & f) ^ (~e & g);
                uint32_t t1 = hh + S1 + ch + k[i] + w[i];
                uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t t2 = S0 + mj;
                hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
            }
            h[0] += a; h[1] += b; h[2] += c; h[3] += d;
            h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
        }

        char buf[65];
        for (int i = 0; i < 8; ++i) snprintf(buf + i * 8, 9, "%08x", h[i]);
        return string(buf);
    }
};

class PasswordHasher {
public:
    static string makeSalt() {
        random_device rd;
        mt19937_64 gen(((uint64_t)rd() << 32) ^ rd() ^ (uint64_t)nowMs());
        static const char* digits = "0123456789abcdef";
        string salt;
        for (int i = 0; i < 32; ++i) salt += digits[gen() % 16];
        return salt;
    }

    static string hash(const string& salt, const string& password) {
        return SHA256::hash(salt + password);
    }

    static bool verify(const string& salt, const string& password, const string& expected) {
        string got = hash(salt, password);
        if (got.size() != expected.size()) return false;
        unsigned char diff = 0;
        for (size_t i = 0; i < got.size(); ++i) diff |= (unsigned char)(got[i] ^ expected[i]);
        return diff == 0;
    }
};

class User {
public:
    explicit User(string n) : name(std::move(n)) {}
    virtual ~User() = default;
    virtual bool canEditBlacklist() const = 0;
    virtual string role() const = 0;
    const string& getName() const { return name; }

protected:
    string name;
};

class Admin : public User {
public:
    explicit Admin(string n) : User(std::move(n)) {}
    bool canEditBlacklist() const override { return true; }
    string role() const override { return "Admin"; }
};

class Analyst : public User {
public:
    explicit Analyst(string n) : User(std::move(n)) {}
    bool canEditBlacklist() const override { return false; }
    string role() const override { return "Analyst"; }
};

struct UserRecord {
    string username;
    string salt;
    string hash;
    string role;
    int failedAttempts = 0;
    long long lockedUntilMs = 0;
    int lockRounds = 0;
};

class AuthManager {
public:
    static const int MAX_FAILS = 3;

    explicit AuthManager(string file, long long baseLockMs = 30000)
        : path(std::move(file)), baseLock(baseLockMs) {
        load();
    }

    bool hasUsers() const { return !users.empty(); }

    bool bootstrapAdmin(const string& name, const string& pass) {
        if (!users.empty() || !validNewUser(name, pass)) return false;
        addRecord(name, pass, "Admin");
        return true;
    }

    bool registerUser(const User& by, const string& name, const string& pass, const string& role) {
        if (!by.canEditBlacklist()) {
            lastMessage = "Refused: only an Admin can register users";
            return false;
        }
        if (role != "Admin" && role != "Analyst") {
            lastMessage = "Unknown role";
            return false;
        }
        if (!validNewUser(name, pass)) return false;
        addRecord(name, pass, role);
        return true;
    }

    unique_ptr<User> login(const string& user, const string& pass, long long now = nowMs()) {
        map<string, UserRecord>::iterator it = users.find(user);
        if (it == users.end()) {
            lastMessage = "Unknown user or wrong password";
            return nullptr;
        }
        UserRecord& r = it->second;

        if (r.lockedUntilMs > now) {
            lastMessage = "Account locked for " + to_string((r.lockedUntilMs - now + 999) / 1000) + " more second(s)";
            return nullptr;
        }

        if (PasswordHasher::verify(r.salt, pass, r.hash)) {
            r.failedAttempts = 0;
            r.lockRounds = 0;
            save();
            lastMessage = "Login OK";
            if (r.role == "Admin") return make_unique<Admin>(r.username);
            return make_unique<Analyst>(r.username);
        }

        r.failedAttempts++;
        lastMessage = "Unknown user or wrong password (" + to_string(r.failedAttempts) + "/" + to_string(MAX_FAILS) + ")";
        if (r.failedAttempts >= MAX_FAILS) {
            r.lockRounds++;
            long long ms = baseLock * (1LL << (r.lockRounds - 1));
            r.lockedUntilMs = now + ms;
            r.failedAttempts = 0;
            lastMessage = "Too many failures: account locked for " + to_string(ms / 1000) + " s";
        }
        save();
        return nullptr;
    }

    bool isLocked(const string& user, long long now = nowMs()) const {
        map<string, UserRecord>::const_iterator it = users.find(user);
        return it != users.end() && it->second.lockedUntilMs > now;
    }

    string lastMessage;

private:
    string path;
    long long baseLock;
    map<string, UserRecord> users;

    bool validNewUser(const string& name, const string& pass) {
        if (name.empty() || name.find_first_of(" \t\n") != string::npos) {
            lastMessage = "Bad username";
            return false;
        }
        if (pass.size() < 6) {
            lastMessage = "Password too short (minimum 6 characters)";
            return false;
        }
        if (users.count(name)) {
            lastMessage = "Username already exists";
            return false;
        }
        return true;
    }

    void addRecord(const string& name, const string& pass, const string& role) {
        UserRecord r;
        r.username = name;
        r.role = role;
        r.salt = PasswordHasher::makeSalt();
        r.hash = PasswordHasher::hash(r.salt, pass);
        users[name] = r;
        save();
        lastMessage = "Registered " + name + " as " + role;
    }

    void save() const {
        ofstream out(path.c_str());
        for (map<string, UserRecord>::const_iterator it = users.begin(); it != users.end(); ++it) {
            const UserRecord& r = it->second;
            out << r.username << ' ' << r.salt << ' ' << r.hash << ' ' << r.role << ' '
                << r.failedAttempts << ' ' << r.lockedUntilMs << ' ' << r.lockRounds << '\n';
        }
    }

    void load() {
        ifstream in(path.c_str());
        string line;
        while (getline(in, line)) {
            istringstream ss(line);
            UserRecord r;
            if (ss >> r.username >> r.salt >> r.hash >> r.role >> r.failedAttempts >> r.lockedUntilMs >> r.lockRounds)
                users[r.username] = r;
        }
    }
};

class SessionManager {
public:
    explicit SessionManager(long long ttlMs = 30LL * 60 * 1000) : ttl(ttlMs) {}

    string create(const string& username, long long now = nowMs()) {
        random_device rd;
        mt19937_64 gen(((uint64_t)rd() << 32) ^ rd() ^ (uint64_t)now);
        static const char* digits = "0123456789abcdef";
        string token;
        for (int i = 0; i < 32; ++i) token += digits[gen() % 16];
        sessions[token] = make_pair(username, now + ttl);
        return token;
    }

    bool validate(const string& token, string& userOut, long long now = nowMs()) {
        map<string, pair<string, long long> >::iterator it = sessions.find(token);
        if (it == sessions.end()) return false;
        if (it->second.second < now) {
            sessions.erase(it);
            return false;
        }
        userOut = it->second.first;
        return true;
    }

    void destroy(const string& token) { sessions.erase(token); }

private:
    long long ttl;
    map<string, pair<string, long long> > sessions;
};

static AuthManager* gAuth = nullptr;
static SessionManager* gSessions = nullptr;
static map<string, string> gTokenRole;

static void copyOut(char* dest, int size, const string& s)
{
    if (dest == NULL || size <= 0)
        return;
    strncpy(dest, s.c_str(), size - 1);
    dest[size - 1] = '\0';
}

void authInit(const char* usersFile)
{
    gAuth = new AuthManager(usersFile, 30000);
    gSessions = new SessionManager();

    if (!gAuth->hasUsers()) {
        gAuth->bootstrapAdmin("admin", "Admin@123");
        unique_ptr<User> a = gAuth->login("admin", "Admin@123");
        gAuth->registerUser(*a, "analyst", "Analyst@123", "Analyst");
    }
}

bool authLogin(const char* user, const char* pass, char* role, int roleSize, char* msg, int msgSize)
{
    unique_ptr<User> u = gAuth->login(user, pass);
    copyOut(msg, msgSize, gAuth->lastMessage);
    if (!u)
        return false;
    copyOut(role, roleSize, u->role());
    return true;
}

bool authRegister(const char* byUser, const char* byRole, const char* newUser,
                  const char* newPass, const char* newRole, char* msg, int msgSize)
{
    unique_ptr<User> by;
    if (strcmp(byRole, "Admin") == 0)
        by.reset(new Admin(byUser));
    else
        by.reset(new Analyst(byUser));

    bool ok = gAuth->registerUser(*by, newUser, newPass, newRole);
    copyOut(msg, msgSize, gAuth->lastMessage);
    return ok;
}

bool authCanEdit(const char* role)
{
    return strcmp(role, "Admin") == 0;
}

bool authStartSession(const char* user, const char* role, char* token, int tokenSize)
{
    string t = gSessions->create(user);
    gTokenRole[t] = role;
    copyOut(token, tokenSize, t);
    return true;
}

bool authCheckSession(const char* token, char* user, int userSize, char* role, int roleSize)
{
    string who;
    if (!gSessions->validate(token, who))
        return false;
    map<string, string>::iterator it = gTokenRole.find(token);
    if (it == gTokenRole.end())
        return false;
    copyOut(user, userSize, who);
    copyOut(role, roleSize, it->second);
    return true;
}

void authEndSession(const char* token)
{
    gSessions->destroy(token);
    gTokenRole.erase(token);
}
