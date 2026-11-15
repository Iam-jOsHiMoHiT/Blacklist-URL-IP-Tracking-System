#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <cstring>
#include "but_header.hpp"

void safeCopy(char* dest, const char* src, int destSize)
{
    if (dest == NULL || destSize <= 0)
        return;
    if (src == NULL) {
        dest[0] = '\0';
        return;
    }
    int i = 0;
    while (i < destSize - 1 && src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

void toLowerStr(char* s)
{
    for (; *s != '\0'; s++)
        *s = (char)tolower((unsigned char)*s);
}

void trimStr(char* s)
{
    int len = (int)strlen(s);
    int start = 0;
    while (s[start] != '\0' && isspace((unsigned char)s[start]))
        start++;
    int end = len;
    while (end > start && isspace((unsigned char)s[end - 1]))
        end--;
    int n = end - start;
    if (start > 0)
        memmove(s, s + start, n);
    s[n] = '\0';
}

bool isValidUrl(const char* s)
{
    return s != NULL && s[0] != '\0' && strlen(s) < (size_t)MAX_URL;
}

bool parseIPv4(const char* s, unsigned int& out)
{
    unsigned int result = 0;
    int parts = 0;
    int i = 0;

    while (true) {
        int start = i;
        int value = 0;
        while (isdigit((unsigned char)s[i])) {
            value = value * 10 + (s[i] - '0');
            i++;
            if (i - start > 3)
                return false;
        }
        int len = i - start;
        if (len == 0)
            return false;
        if (len > 1 && s[start] == '0')
            return false;
        if (value > 255)
            return false;

        result = (result << 8) | (unsigned int)value;
        parts++;

        if (s[i] == '.') {
            if (parts == 4)
                return false;
            i++;
            continue;
        }
        if (s[i] == '\0')
            break;
        return false;
    }

    if (parts != 4)
        return false;
    out = result;
    return true;
}

static bool validHost(const char* host)
{
    char h[MAX_LINE];
    safeCopy(h, host, MAX_LINE);

    char* colon = strrchr(h, ':');
    if (colon != NULL) {
        if (colon[1] == '\0')
            return false;
        for (char* p = colon + 1; *p != '\0'; p++)
            if (!isdigit((unsigned char)*p))
                return false;
        *colon = '\0';
    }

    int len = (int)strlen(h);
    if (len == 0 || h[0] == '.' || h[len - 1] == '.')
        return false;
    if (strstr(h, "..") != NULL)
        return false;
    if (strchr(h, '.') == NULL)
        return false;

    bool numericOnly = true;
    for (int i = 0; i < len; i++) {
        char c = h[i];
        if (!isalnum((unsigned char)c) && c != '-' && c != '.')
            return false;
        if (!isdigit((unsigned char)c) && c != '.')
            numericOnly = false;
    }

    if (numericOnly) {
        unsigned int tmp;
        return parseIPv4(h, tmp);
    }
    return true;
}

int normalizeInput(const char* raw, char* out, int outSize)
{
    if (out == NULL || outSize <= 0)
        return INPUT_INVALID;
    out[0] = '\0';

    if (raw == NULL || strlen(raw) >= (size_t)MAX_LINE)
        return INPUT_INVALID;

    char buf[MAX_LINE];
    safeCopy(buf, raw, MAX_LINE);
    trimStr(buf);

    if (buf[0] == '\0')
        return INPUT_INVALID;
    for (char* p = buf; *p != '\0'; p++)
        if (isspace((unsigned char)*p))
            return INPUT_INVALID;

    char* slash = strchr(buf, '/');
    if (slash != NULL) {
        int ipLen = (int)(slash - buf);
        if (ipLen > 0 && ipLen < 32) {
            char ip[32];
            memcpy(ip, buf, ipLen);
            ip[ipLen] = '\0';

            unsigned int num;
            const char* bitsText = slash + 1;
            bool digitsOnly = bitsText[0] != '\0';
            for (const char* p = bitsText; *p != '\0'; p++)
                if (!isdigit((unsigned char)*p))
                    digitsOnly = false;

            if (parseIPv4(ip, num) && digitsOnly) {
                if (strlen(bitsText) > 2)
                    return INPUT_INVALID;
                int bits = atoi(bitsText);
                if (bits < 1 || bits > 32)
                    return INPUT_INVALID;
                if ((int)strlen(buf) >= outSize)
                    return INPUT_INVALID;
                safeCopy(out, buf, outSize);
                return INPUT_CIDR;
            }
        }
    }

    unsigned int ipNum;
    if (parseIPv4(buf, ipNum)) {
        if ((int)strlen(buf) >= outSize)
            return INPUT_INVALID;
        safeCopy(out, buf, outSize);
        return INPUT_IPV4;
    }

    char* p = buf;
    char* scheme = strstr(buf, "://");
    if (scheme != NULL && scheme != buf) {
        bool okScheme = true;
        for (char* c = buf; c < scheme; c++)
            if (!isalnum((unsigned char)*c) && *c != '+' && *c != '-' && *c != '.')
                okScheme = false;
        if (okScheme)
            p = scheme + 3;
    }

    char* hashPos = strchr(p, '#');
    if (hashPos != NULL)
        *hashPos = '\0';

    int cut = (int)strcspn(p, "/?");
    char host[MAX_LINE];
    char rest[MAX_LINE];
    memcpy(host, p, cut);
    host[cut] = '\0';
    safeCopy(rest, p + cut, MAX_LINE);

    char* at = strrchr(host, '@');
    if (at != NULL)
        memmove(host, at + 1, strlen(at + 1) + 1);

    toLowerStr(host);

    char* colon = strrchr(host, ':');
    if (colon != NULL && (strcmp(colon + 1, "80") == 0 || strcmp(colon + 1, "443") == 0))
        *colon = '\0';

    if (strncmp(host, "www.", 4) == 0)
        memmove(host, host + 4, strlen(host + 4) + 1);

    if (!validHost(host))
        return INPUT_INVALID;

    char* q = strchr(rest, '?');
    int pathLen = (q == NULL) ? (int)strlen(rest) : (int)(q - rest);
    if (pathLen > 0 && rest[pathLen - 1] == '/')
        pathLen--;

    int total = (int)strlen(host) + pathLen + (q == NULL ? 0 : (int)strlen(q));
    if (total >= outSize || total >= MAX_URL)
        return INPUT_INVALID;

    int pos = 0;
    int hostLen = (int)strlen(host);
    memcpy(out + pos, host, hostLen);
    pos += hostLen;
    memcpy(out + pos, rest, pathLen);
    pos += pathLen;
    if (q != NULL) {
        int qLen = (int)strlen(q);
        memcpy(out + pos, q, qLen);
        pos += qLen;
    }
    out[pos] = '\0';

    unsigned int again;
    if (parseIPv4(out, again))
        return INPUT_IPV4;
    return INPUT_URL;
}

void extractHost(const char* clean, char* host, int hostSize)
{
    int cut = (int)strcspn(clean, "/?");
    if (cut >= hostSize)
        cut = hostSize - 1;
    memcpy(host, clean, cut);
    host[cut] = '\0';

    char* colon = strrchr(host, ':');
    if (colon != NULL)
        *colon = '\0';
}

Engine::Engine() : table(20011), cache(100)
{
    entryCap = 1024;
    entries = new char*[entryCap];
    entryCount = 0;
    checkedCount = 0;
    blockedCount = 0;
    cacheHits = 0;
    bloomSkips = 0;
}

Engine::~Engine()
{
    for (int i = 0; i < entryCount; i++)
        delete[] entries[i];
    delete[] entries;
}

void Engine::remember(const char* clean)
{
    if (entryCount == entryCap) {
        int newCap = entryCap * 2;
        char** bigger = new char*[newCap];
        for (int i = 0; i < entryCount; i++)
            bigger[i] = entries[i];
        delete[] entries;
        entries = bigger;
        entryCap = newCap;
    }
    entries[entryCount] = new char[strlen(clean) + 1];
    strcpy(entries[entryCount], clean);
    entryCount++;
}

int Engine::addEntry(const char* raw, char* cleanOut)
{
    char clean[MAX_URL];
    int type = normalizeInput(raw, clean, MAX_URL);
    if (cleanOut != NULL)
        safeCopy(cleanOut, clean, MAX_URL);

    if (type == INPUT_INVALID)
        return ADD_INVALID;

    if (type == INPUT_CIDR) {
        if (!cidrs.add(clean))
            return ADD_DUPLICATE;
        cache.clear();
        return ADD_CIDR;
    }

    if (!table.insert(clean))
        return ADD_DUPLICATE;

    bloom.insert(clean);
    remember(clean);
    cache.clear();
    return ADD_NEW;
}

int Engine::check(const char* raw, char* clean, char* reason, int reasonSize)
{
    int type = normalizeInput(raw, clean, MAX_URL);
    if (type == INPUT_INVALID || type == INPUT_CIDR) {
        snprintf(reason, reasonSize, "not a valid URL or IPv4 address");
        return RESULT_INVALID;
    }

    checkedCount++;

    char verdict[10];
    if (cache.get(clean, verdict)) {
        cacheHits++;
        bool wasBlocked = (strcmp(verdict, "BLOCKED") == 0);
        if (wasBlocked)
            blockedCount++;
        snprintf(reason, reasonSize, "cached result");
        return wasBlocked ? RESULT_BLOCKED : RESULT_ALLOWED;
    }

    bool blocked = false;
    reason[0] = '\0';

    if (type == INPUT_IPV4) {

        if (bloom.check(clean)) {
            if (table.search(clean)) {
                blocked = true;
                snprintf(reason, reasonSize, "blacklisted IP");
            }
        } else {
            bloomSkips++;
        }

        if (!blocked) {
            unsigned int ip;
            parseIPv4(clean, ip);
            int len = cidrs.match(ip);
            if (len > 0) {
                blocked = true;
                snprintf(reason, reasonSize, "inside blacklisted range /%d", len);
            }
        }
    } else {
        char host[MAX_URL];
        extractHost(clean, host, MAX_URL);

        if (!bloom.check(clean) && !bloom.check(host)) {
            bloomSkips++;
        } else if (table.search(clean)) {
            blocked = true;
            snprintf(reason, reasonSize, strcmp(clean, host) == 0 ? "blacklisted domain" : "blacklisted URL");
        } else if (table.search(host)) {
            blocked = true;
            snprintf(reason, reasonSize, "blacklisted domain");
        }
    }

    if (!blocked)
        snprintf(reason, reasonSize, "not in blacklist");

    cache.put(clean, blocked ? "BLOCKED" : "ALLOWED");
    if (blocked)
        blockedCount++;
    return blocked ? RESULT_BLOCKED : RESULT_ALLOWED;
}
