#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cmath>
#include "but_header.hpp"

static const char* FEATURE_NAMES[ML_FEATURES] = {
    "url_length", "https", "http", "dot_count", "digit_count", "hyphen_count",
    "has_ip", "at_count", "path_length", "special_count", "suspicious_count"
};

MLChecker::MLChecker()
{
    loaded = false;
    intercept = 0;
    scored = 0;
    flagged = 0;
    for (int i = 0; i < ML_FEATURES; i++) {
        median[i] = 0;
        mean[i] = 0;
        scale[i] = 1;
        weight[i] = 0;
    }
}

bool MLChecker::load(const char* path)
{
    loaded = false;
    FILE* f = fopen(path, "r");
    if (f == NULL)
        return false;

    char line[MAX_LINE];
    int got = 0;
    bool haveIntercept = false;

    while (fgets(line, MAX_LINE, f) != NULL) {
        trimStr(line);
        if (line[0] == '\0' || line[0] == '#')
            continue;

        char name[64];
        double a, b, c, d;
        if (got < ML_FEATURES && sscanf(line, "%63s %lf %lf %lf %lf", name, &a, &b, &c, &d) == 5
            && strcmp(name, FEATURE_NAMES[got]) == 0) {
            median[got] = a;
            mean[got] = b;
            scale[got] = c;
            weight[got] = d;
            got++;
        } else if (sscanf(line, "%63s %lf", name, &a) == 2 && strcmp(name, "intercept") == 0) {
            intercept = a;
            haveIntercept = true;
        } else {
            fclose(f);
            return false;
        }
    }
    fclose(f);

    loaded = (got == ML_FEATURES && haveIntercept);
    return loaded;
}

void MLChecker::extractFeatures(const char* url, double* f)
{

    char netloc[MAX_LINE + 16];
    char path[MAX_LINE + 16];
    char host[MAX_LINE + 16];

    const char* p = strstr(url, "://") + 3;
    int netlocLen = (int)strcspn(p, "/?#");
    memcpy(netloc, p, netlocLen);
    netloc[netlocLen] = '\0';

    const char* rest = p + netlocLen;
    int pathLen = (int)strcspn(rest, "?#");
    memcpy(path, rest, pathLen);
    path[pathLen] = '\0';

    char* lastSlash = strrchr(path, '/');
    char* semi = strchr(lastSlash != NULL ? lastSlash : path, ';');
    if (semi != NULL)
        *semi = '\0';

    const char* hostPart = netloc;
    char* at = strrchr(netloc, '@');
    if (at != NULL)
        hostPart = at + 1;

    int h = 0;
    if (hostPart[0] == '[') {
        for (int i = 1; hostPart[i] != '\0' && hostPart[i] != ']'; i++)
            host[h++] = hostPart[i];
    } else {
        for (int i = 0; hostPart[i] != '\0' && hostPart[i] != ':'; i++)
            host[h++] = hostPart[i];
    }
    host[h] = '\0';
    toLowerStr(host);

    int hasIp = 0;
    unsigned int tmp;
    if (host[0] != '\0') {
        if (parseIPv4(host, tmp)) {
            hasIp = 1;
        } else if (strchr(host, ':') != NULL) {
            int colons = 0;
            bool ok = true;
            for (int i = 0; host[i] != '\0'; i++) {
                if (host[i] == ':')
                    colons++;
                else if (!isxdigit((unsigned char)host[i]) && host[i] != '.')
                    ok = false;
            }
            hasIp = (ok && colons >= 2) ? 1 : 0;
        }
    }

    int len = (int)strlen(url);
    int dots = 0, digits = 0, hyphens = 0, ats = 0, special = 0;
    for (int i = 0; i < len; i++) {
        unsigned char c = (unsigned char)url[i];
        if (c == '.') dots++;
        if (c == '-') hyphens++;
        if (c == '@') ats++;
        if (isdigit(c)) digits++;
        if (!isalnum(c)) special++;
    }

    char lower[MAX_LINE + 16];
    safeCopy(lower, url, MAX_LINE + 16);
    toLowerStr(lower);

    static const char* words[6] = { "login", "verify", "secure", "update", "password", "bank" };
    int suspicious = 0;
    for (int i = 0; i < 6; i++)
        if (strstr(lower, words[i]) != NULL)
            suspicious++;

    f[0]  = len;
    f[1]  = (strncmp(lower, "https://", 8) == 0) ? 1 : 0;
    f[2]  = (strncmp(lower, "http://", 7) == 0) ? 1 : 0;
    f[3]  = dots;
    f[4]  = digits;
    f[5]  = hyphens;
    f[6]  = hasIp;
    f[7]  = ats;
    f[8]  = (int)strlen(path);
    f[9]  = special;
    f[10] = suspicious;
}

double MLChecker::spamProbability(const char* rawInput)
{
    if (!loaded || rawInput == NULL)
        return -1;

    char clean[MAX_URL];
    if (normalizeInput(rawInput, clean, MAX_URL) != INPUT_URL)
        return -1;

    char buf[MAX_LINE];
    safeCopy(buf, rawInput, MAX_LINE);
    trimStr(buf);

    bool hasScheme = false;
    const char* sch = strstr(buf, "://");
    if (sch != NULL && sch != buf) {
        hasScheme = true;
        for (const char* c = buf; c < sch; c++)
            if (!isalnum((unsigned char)*c) && *c != '+' && *c != '-' && *c != '.')
                hasScheme = false;
    }

    char full[MAX_LINE + 16];
    if (hasScheme)
        safeCopy(full, buf, MAX_LINE + 16);
    else
        snprintf(full, sizeof(full), "https://%s", buf);

    double f[ML_FEATURES];
    extractFeatures(full, f);

    double logit = intercept;
    for (int i = 0; i < ML_FEATURES; i++) {
        double s = (scale[i] == 0) ? 1 : scale[i];
        logit += weight[i] * ((f[i] - mean[i]) / s);
    }

    return 1.0 / (1.0 + exp(logit));
}

int checkWithML(Engine& engine, MLChecker& ml, const char* raw,
                char* clean, char* reason, int reasonSize, double& mlSpam)
{
    mlSpam = -1;

    int result = engine.check(raw, clean, reason, reasonSize);
    if (result == RESULT_INVALID)
        return result;

    mlSpam = ml.spamProbability(raw);
    if (mlSpam >= 0) {
        ml.scored++;
        if (mlSpam >= ML_WARN_THRESHOLD)
            ml.flagged++;
    }
    return result;
}
