#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include "but_header.hpp"
#include "Auth.hpp"

static bool readLine(const char* prompt, char* buf, int size)
{
    std::cout << prompt;
    if (!std::cin.getline(buf, size)) {
        if (std::cin.eof())
            return false;
        std::cin.clear();
        std::cin.ignore(10000, '\n');
        buf[0] = '\0';
        std::cout << "Input too long.\n";
    }
    return true;
}

static void processQueue(Queue& queue, Engine& engine, MLChecker& ml, data& store, display& ui, bool verbose)
{
    int allowed = 0, blocked = 0, invalid = 0, saveFailed = 0;
    char request[MAX_URL];
    char clean[MAX_URL];
    char reason[96];
    double mlSpam;

    while (queue.dequeue(request)) {
        int r = checkWithML(engine, ml, request, clean, reason, sizeof(reason), mlSpam);

        if (r == RESULT_INVALID) {
            invalid++;
            if (verbose)
                ui.displayInvalid(request);
            continue;
        }

        if (r == RESULT_BLOCKED)
            blocked++;
        else
            allowed++;

        if (verbose)
            ui.displayResult(clean, r == RESULT_BLOCKED, reason, mlSpam);

        if (!store.saveResult(clean, r == RESULT_BLOCKED))
            saveFailed++;
    }

    if (!verbose || allowed + blocked + invalid > 1)
        std::cout << "Done: " << (allowed + blocked + invalid) << " processed | "
                  << blocked << " blocked | " << allowed << " allowed | "
                  << invalid << " invalid\n";
    if (saveFailed > 0)
        std::cout << "Warning: could not write " << saveFailed << " result(s) to the history file.\n";
}

static void checkOne(Queue& queue, Engine& engine, MLChecker& ml, data& store, display& ui)
{
    char input[MAX_LINE];
    if (!readLine("Enter URL or IP: ", input, MAX_LINE))
        return;
    trimStr(input);
    if (input[0] == '\0') {
        std::cout << "Nothing entered.\n";
        return;
    }
    queue.enqueue(input);
    processQueue(queue, engine, ml, store, ui, true);
}

static void checkFromFile(Queue& queue, Engine& engine, MLChecker& ml, data& store, display& ui)
{
    char path[MAX_LINE];
    if (!readLine("File with one URL/IP per line: ", path, MAX_LINE))
        return;
    trimStr(path);

    FILE* f = fopen(path, "r");
    if (f == NULL) {
        std::cout << "Cannot open '" << path << "'.\n";
        return;
    }

    char line[MAX_LINE];
    int queued = 0;
    while (fgets(line, MAX_LINE, f) != NULL) {
        trimStr(line);
        if (line[0] == '\0' || line[0] == '#')
            continue;
        if (queue.enqueue(line))
            queued++;
    }
    fclose(f);

    std::cout << queued << " request(s) queued.\n";

    processQueue(queue, engine, ml, store, ui, queued <= 50);
}

static void viewHistory(data& store, display& ui)
{
    static char lines[20][MAX_LINE];
    int n = store.getHistory(lines, 20);
    ui.displayHistory(lines, n);
}

static void addEntry(Engine& engine, data& store, const char* role)
{
    if (!authCanEdit(role)) {
        std::cout << "Refused: only an Admin can edit the blacklist (you are an " << role << ").\n";
        return;
    }

    char input[MAX_LINE];
    char clean[MAX_URL];
    if (!readLine("Blacklist entry to add (URL, IP or CIDR range): ", input, MAX_LINE))
        return;
    trimStr(input);

    int r = engine.addEntry(input, clean);
    if (r == ADD_INVALID) {
        std::cout << "Not a valid URL, IPv4 address or CIDR range.\n";
    } else if (r == ADD_DUPLICATE) {
        std::cout << "'" << clean << "' is already blacklisted.\n";
    } else {
        if (store.appendBlacklist(clean))
            std::cout << "Added '" << clean << "' to the blacklist.\n";
        else
            std::cout << "Added '" << clean << "' for this session, but the blacklist file could not be written.\n";
    }
}

static void registerUser(const char* username, const char* role)
{
    if (!authCanEdit(role)) {
        std::cout << "Refused: only an Admin can register users (you are an " << role << ").\n";
        return;
    }

    char name[MAX_LINE], pass[MAX_LINE], newRole[MAX_LINE], msg[128];
    if (!readLine("New username: ", name, MAX_LINE))
        return;
    if (!readLine("Password (min 6 characters): ", pass, MAX_LINE))
        return;
    if (!readLine("Role (Admin/Analyst): ", newRole, MAX_LINE))
        return;

    authRegister(username, role, name, pass, newRole, msg, sizeof(msg));
    std::cout << msg << "\n";
}

static void runBenchmark(Engine& engine)
{
    int n = engine.entryCount;
    if (n == 0) {
        std::cout << "Blacklist is empty, nothing to benchmark.\n";
        return;
    }

    const int Q = 200;
    const int ROUNDS = 100;

    char (*queries)[MAX_URL] = new char[Q][MAX_URL];
    for (int i = 0; i < Q; i++) {
        if (i % 2 == 0)
            safeCopy(queries[i], engine.entries[(i * 37) % n], MAX_URL);
        else
            snprintf(queries[i], MAX_URL, "not-listed-%d.benchmark.test", i);
    }

    long hashFound = 0;
    clock_t t0 = clock();
    for (int r = 0; r < ROUNDS; r++)
        for (int i = 0; i < Q; i++)
            if (engine.table.search(queries[i]))
                hashFound++;
    clock_t t1 = clock();

    long linearFound = 0;
    clock_t t2 = clock();
    for (int i = 0; i < Q; i++)
        for (int j = 0; j < n; j++)
            if (strcmp(engine.entries[j], queries[i]) == 0) {
                linearFound++;
                break;
            }
    clock_t t3 = clock();

    double hashUs   = 1e6 * (double)(t1 - t0) / CLOCKS_PER_SEC / (double)(ROUNDS * Q);
    double linearUs = 1e6 * (double)(t3 - t2) / CLOCKS_PER_SEC / (double)Q;

    std::cout << "---- Benchmark: " << n << " entries, " << Q << " lookups ----\n";
    std::cout << "Hash table    : " << hashUs << " us per lookup\n";
    std::cout << "Linear search : " << linearUs << " us per lookup\n";
    if (hashUs > 0)
        std::cout << "Hash table is about " << (long)(linearUs / hashUs) << "x faster\n";
    std::cout << "Sanity check  : both found " << (hashFound / ROUNDS) << " / " << linearFound
              << (hashFound / ROUNDS == linearFound ? " (match)\n" : " (MISMATCH!)\n");

    delete[] queries;
}

int main(int argc, char* argv[])
{
    const char* blacklistPath = (argc > 1) ? argv[1] : "blacklist.txt";
    const char* historyPath   = (argc > 2) ? argv[2] : "history.txt";

    std::cout << "======================================\n";
    std::cout << "  Blacklist URL/IP Tracking System\n";
    std::cout << "======================================\n";

    authInit("users.db");

    char username[MAX_LINE] = "";
    char password[MAX_LINE];
    char role[32] = "";
    char msg[128];
    bool loggedIn = false;

    for (int attempt = 0; attempt < 3 && !loggedIn; attempt++) {
        if (!readLine("Enter username: ", username, MAX_LINE) ||
            !readLine("Enter password: ", password, MAX_LINE))
            break;
        loggedIn = authLogin(username, password, role, sizeof(role), msg, sizeof(msg));
        std::cout << (loggedIn ? "Login successful. " : "X ") << msg << "\n";
    }
    if (!loggedIn) {
        std::cout << "Access denied. Exiting.\n";
        return 1;
    }
    std::cout << "Logged in as " << username << " (" << role << ")\n";

    Engine engine;
    data store(blacklistPath, historyPath);
    LoadSummary s;

    std::cout << "\nLoading blacklist from '" << blacklistPath << "' ...\n";
    if (!store.loadBlacklist(engine, s)) {
        std::cout << "Could not open '" << blacklistPath << "'. Starting with an empty blacklist; "
                  << "use menu option 5 to add entries.\n";
    } else {
        std::cout << "Lines read : " << s.read << "\n";
        std::cout << "Loaded     : " << s.loaded << " (" << s.cidrs << " CIDR ranges)\n";
        std::cout << "Duplicates : " << s.duplicates << "\n";
        std::cout << "Invalid    : " << s.invalid << "\n";
        std::cout << "Skipped    : " << s.skipped << " (blank lines / comments)\n";
    }

    MLChecker ml;
    if (ml.load("ml_url_checker/ml_weights.txt") || ml.load("ml_weights.txt"))
        std::cout << "ML model loaded (logistic regression, " << ML_FEATURES << " features).\n";
    else
        std::cout << "ML model not found (ml_url_checker/ml_weights.txt) - continuing without ML.\n";

    Queue queue;
    display ui;
    char choiceText[MAX_LINE];

    while (true) {
        ui.showMenu();
        if (!readLine("Choice: ", choiceText, MAX_LINE))
            break;
        trimStr(choiceText);
        if (choiceText[0] == '\0')
            continue;

        int choice = (choiceText[1] == '\0' && choiceText[0] >= '0' && choiceText[0] <= '9')
                         ? choiceText[0] - '0' : -1;

        if (choice == 0) {
            std::cout << "Goodbye, " << username << ".\n";
            break;
        }

        switch (choice) {
            case 1: checkOne(queue, engine, ml, store, ui);        break;
            case 2: checkFromFile(queue, engine, ml, store, ui);   break;
            case 3: viewHistory(store, ui);                        break;
            case 4:
                ui.displayStats(engine.table.size(), engine.cidrs.size(),
                                engine.table.loadFactor(), engine.table.longestChain(),
                                engine.checkedCount, engine.blockedCount,
                                engine.cacheHits, engine.bloomSkips,
                                ml.scored, ml.flagged);
                break;
            case 5: addEntry(engine, store, role);                 break;
            case 6: runBenchmark(engine);                          break;
            case 7: engine.table.displayTable();                   break;
            case 8: registerUser(username, role);                  break;
            default: std::cout << "Invalid choice, enter 0-8.\n";
        }
    }

    return 0;
}
