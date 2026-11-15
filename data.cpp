#include <cstdio>
#include <cstring>
#include <ctime>
#include "but_header.hpp"

data::data(const char* blacklistPath, const char* historyPath)
{
    safeCopy(blacklistFile, blacklistPath, MAX_URL);
    safeCopy(historyFile, historyPath, MAX_URL);
}

bool data::loadBlacklist(Engine& engine, LoadSummary& summary)
{
    summary.read = 0;
    summary.loaded = 0;
    summary.duplicates = 0;
    summary.invalid = 0;
    summary.skipped = 0;
    summary.cidrs = 0;

    FILE* f = fopen(blacklistFile, "r");
    if (f == NULL)
        return false;

    char line[MAX_LINE];
    while (fgets(line, MAX_LINE, f) != NULL) {
        summary.read++;

        bool tooLong = (strchr(line, '\n') == NULL && !feof(f));
        if (tooLong) {
            int c;
            while ((c = fgetc(f)) != EOF && c != '\n')
                ;
            summary.invalid++;
            continue;
        }

        trimStr(line);
        if (line[0] == '\0' || line[0] == '#') {
            summary.skipped++;
            continue;
        }

        char clean[MAX_URL];
        int r = engine.addEntry(line, clean);
        if (r == ADD_NEW)
            summary.loaded++;
        else if (r == ADD_CIDR) {
            summary.loaded++;
            summary.cidrs++;
        } else if (r == ADD_DUPLICATE)
            summary.duplicates++;
        else
            summary.invalid++;
    }

    fclose(f);
    return true;
}

bool data::appendBlacklist(const char* clean)
{
    FILE* f = fopen(blacklistFile, "a");
    if (f == NULL)
        return false;
    fprintf(f, "%s\n", clean);
    fclose(f);
    return true;
}

bool data::saveResult(const char* url, bool blocked)
{
    FILE* f = fopen(historyFile, "a");
    if (f == NULL)
        return false;

    char stamp[32];
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", t);

    fprintf(f, "%s | %s | %s\n", stamp, blocked ? "BLOCKED" : "ALLOWED", url);
    fclose(f);
    return true;
}

int data::getHistory(char lines[][MAX_LINE], int maxLines)
{
    if (maxLines <= 0)
        return 0;

    FILE* f = fopen(historyFile, "r");
    if (f == NULL)
        return 0;

    char buf[MAX_LINE];
    int total = 0;
    while (fgets(buf, MAX_LINE, f) != NULL) {
        trimStr(buf);
        if (buf[0] == '\0')
            continue;
        safeCopy(lines[total % maxLines], buf, MAX_LINE);
        total++;
    }
    fclose(f);

    int count = (total < maxLines) ? total : maxLines;
    if (total > maxLines) {
        int start = total % maxLines;
        char (*tmp)[MAX_LINE] = new char[count][MAX_LINE];
        for (int i = 0; i < count; i++)
            safeCopy(tmp[i], lines[(start + i) % maxLines], MAX_LINE);
        for (int i = 0; i < count; i++)
            safeCopy(lines[i], tmp[i], MAX_LINE);
        delete[] tmp;
    }
    return count;
}
