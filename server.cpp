#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include "but_header.hpp"
#include "Auth.hpp"

#ifdef _WIN32
    #include <winsock2.h>
    typedef SOCKET sock_t;
    #define CLOSE_SOCKET closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    typedef int sock_t;
    #define CLOSE_SOCKET close
    #define INVALID_SOCKET (-1)
#endif

static void sendAll(sock_t s, const char* buf, int len)
{
    while (len > 0) {
        int n = (int)send(s, buf, len, 0);
        if (n <= 0)
            return;
        buf += n;
        len -= n;
    }
}

static void sendResponse(sock_t c, int code, const char* type, const char* body, int bodyLen)
{
    const char* text = "OK";
    if (code == 401) text = "Unauthorized";
    else if (code == 403) text = "Forbidden";
    else if (code == 404) text = "Not Found";

    char head[256];
    snprintf(head, sizeof(head),
             "HTTP/1.1 %d %s\r\nContent-Type: %s; charset=utf-8\r\n"
             "Content-Length: %d\r\nConnection: close\r\n\r\n",
             code, text, type, bodyLen);
    sendAll(c, head, (int)strlen(head));
    sendAll(c, body, bodyLen);
}

static void sendText(sock_t c, int code, const char* type, const char* body)
{
    sendResponse(c, code, type, body, (int)strlen(body));
}

static void sendJson(sock_t c, int code, const char* body)
{
    sendText(c, code, "application/json", body);
}

static bool urlDecode(const char* in, char* out, int outSize)
{
    int o = 0;
    for (int i = 0; in[i] != '\0'; i++) {
        char ch = in[i];
        if (ch == '%' && isxdigit((unsigned char)in[i + 1]) && isxdigit((unsigned char)in[i + 2])) {
            char hex[3] = { in[i + 1], in[i + 2], '\0' };
            ch = (char)strtol(hex, NULL, 16);
            i += 2;
        } else if (ch == '+') {
            ch = ' ';
        }
        if (o >= outSize - 1)
            return false;
        out[o++] = ch;
    }
    out[o] = '\0';
    return true;
}

static bool getParam(const char* s, const char* name, char* out, int outSize)
{
    int nameLen = (int)strlen(name);
    for (int i = 0; s[i] != '\0'; i++) {
        bool startsParam = (i == 0 || s[i - 1] == '?' || s[i - 1] == '&');
        if (startsParam && strncmp(s + i, name, nameLen) == 0 && s[i + nameLen] == '=') {
            const char* value = s + i + nameLen + 1;
            int len = (int)strcspn(value, "&");
            if (len >= outSize)
                len = outSize - 1;
            memcpy(out, value, len);
            out[len] = '\0';
            return true;
        }
    }
    out[0] = '\0';
    return false;
}

static bool getDecodedParam(const char* s, const char* name, char* out, int outSize)
{
    char raw[1024];
    if (!getParam(s, name, raw, sizeof(raw)))
        return false;
    return urlDecode(raw, out, outSize);
}

static void jsonEscape(const char* in, char* out, int outSize)
{
    int o = 0;
    for (int i = 0; in[i] != '\0' && o < outSize - 2; i++) {
        unsigned char ch = (unsigned char)in[i];
        if (ch == '"' || ch == '\\') {
            out[o++] = '\\';
            out[o++] = (char)ch;
        } else if (ch < 32) {
            out[o++] = ' ';
        } else {
            out[o++] = (char)ch;
        }
    }
    out[o] = '\0';
}

static const char* findIgnoreCase(const char* text, const char* word)
{
    int wlen = (int)strlen(word);
    for (int i = 0; text[i] != '\0'; i++) {
        int j = 0;
        while (j < wlen && text[i + j] != '\0' &&
               tolower((unsigned char)text[i + j]) == tolower((unsigned char)word[j]))
            j++;
        if (j == wlen)
            return text + i;
    }
    return NULL;
}

static int readRequest(sock_t c, char* req, int size)
{
    int total = 0;
    while (total < size - 1) {
        int n = (int)recv(c, req + total, size - 1 - total, 0);
        if (n <= 0)
            break;
        total += n;
        req[total] = '\0';

        const char* headerEnd = strstr(req, "\r\n\r\n");
        if (headerEnd != NULL) {
            int contentLength = 0;
            const char* cl = findIgnoreCase(req, "content-length:");
            if (cl != NULL && cl < headerEnd)
                contentLength = atoi(cl + 15);
            int bodyHave = total - (int)(headerEnd + 4 - req);
            if (bodyHave >= contentLength)
                break;
        }
    }
    req[total] = '\0';
    return total;
}

static void sendHomePage(sock_t c)
{
    FILE* f = fopen("web/index.html", "rb");
    if (f == NULL) {
        sendText(c, 404, "text/plain", "web/index.html not found. Run the server from the project folder.");
        return;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char* page = new char[size + 1];
    size_t got = fread(page, 1, size, f);
    fclose(f);

    sendResponse(c, 200, "text/html", page, (int)got);
    delete[] page;
}

struct App {
    Engine* engine;
    MLChecker* ml;
    Queue* queue;
    data* store;
};

static bool requireLogin(sock_t c, const char* query, char* user, int userSize, char* role, int roleSize)
{
    char token[128];
    if (getParam(query, "token", token, sizeof(token)) &&
        authCheckSession(token, user, userSize, role, roleSize))
        return true;

    sendJson(c, 401, "{\"error\":\"Please log in first.\"}");
    return false;
}

static void handleLogin(sock_t c, const char* body)
{
    char user[128], pass[128], role[32], msg[128];
    if (!getDecodedParam(body, "user", user, sizeof(user)) ||
        !getDecodedParam(body, "pass", pass, sizeof(pass))) {
        sendJson(c, 200, "{\"ok\":false,\"message\":\"Enter a username and password.\"}");
        return;
    }

    bool ok = authLogin(user, pass, role, sizeof(role), msg, sizeof(msg));

    char msgJson[300];
    jsonEscape(msg, msgJson, sizeof(msgJson));

    char out[1200];
    if (ok) {
        char token[64];
        authStartSession(user, role, token, sizeof(token));
        char userJson[300];
        jsonEscape(user, userJson, sizeof(userJson));
        snprintf(out, sizeof(out), "{\"ok\":true,\"token\":\"%s\",\"user\":\"%s\",\"role\":\"%s\",\"message\":\"%s\"}",
                 token, userJson, role, msgJson);
    } else {
        snprintf(out, sizeof(out), "{\"ok\":false,\"message\":\"%s\"}", msgJson);
    }
    sendJson(c, 200, out);
}

static void handleCheck(sock_t c, const char* query, App& app)
{
    char user[64], role[32];
    if (!requireLogin(c, query, user, sizeof(user), role, sizeof(role)))
        return;

    char input[MAX_LINE];
    char request[MAX_URL];
    char clean[MAX_URL];
    char reason[96];
    double mlSpam = -1;
    int result = RESULT_INVALID;

    snprintf(reason, sizeof(reason), "not a valid URL or IPv4 address");
    clean[0] = '\0';

    bool decoded = getDecodedParam(query, "url", input, MAX_LINE);

    if (decoded && app.queue->enqueue(input) && app.queue->dequeue(request))
        result = checkWithML(*app.engine, *app.ml, request, clean, reason, sizeof(reason), mlSpam);

    const char* status = "INVALID";
    const char* shown = decoded ? input : "";
    if (result != RESULT_INVALID) {
        status = (result == RESULT_BLOCKED) ? "BLOCKED" : "ALLOWED";
        shown = clean;
        app.store->saveResult(clean, result == RESULT_BLOCKED);
    }

    char urlJson[MAX_LINE * 2];
    char reasonJson[256];
    jsonEscape(shown, urlJson, sizeof(urlJson));
    jsonEscape(reason, reasonJson, sizeof(reasonJson));

    char body[1024];
    snprintf(body, sizeof(body), "{\"status\":\"%s\",\"url\":\"%s\",\"reason\":\"%s\",\"ml\":%.4f}",
             status, urlJson, reasonJson, mlSpam);
    sendJson(c, 200, body);
}

static void handleHistory(sock_t c, const char* query, App& app)
{
    char user[64], role[32];
    if (!requireLogin(c, query, user, sizeof(user), role, sizeof(role)))
        return;

    static char lines[10][MAX_LINE];
    int n = app.store->getHistory(lines, 10);

    static char body[8192];
    int pos = snprintf(body, sizeof(body), "{\"history\":[");
    for (int i = 0; i < n; i++) {
        char esc[MAX_LINE * 2];
        jsonEscape(lines[i], esc, sizeof(esc));
        pos += snprintf(body + pos, sizeof(body) - pos, "%s\"%s\"", i > 0 ? "," : "", esc);
    }
    snprintf(body + pos, sizeof(body) - pos, "]}");
    sendJson(c, 200, body);
}

static void handleAdd(sock_t c, const char* query, App& app)
{
    char user[64], role[32];
    if (!requireLogin(c, query, user, sizeof(user), role, sizeof(role)))
        return;

    if (!authCanEdit(role)) {
        sendJson(c, 403, "{\"ok\":false,\"message\":\"Only an Admin can edit the blacklist.\"}");
        return;
    }

    char input[MAX_LINE];
    char clean[MAX_URL];
    char msg[400] = "";

    if (!getDecodedParam(query, "url", input, MAX_LINE)) {
        sendJson(c, 200, "{\"ok\":false,\"message\":\"Nothing to add.\"}");
        return;
    }

    int r = app.engine->addEntry(input, clean);
    bool ok = false;
    if (r == ADD_INVALID) {
        snprintf(msg, sizeof(msg), "Not a valid URL, IPv4 address or CIDR range.");
    } else if (r == ADD_DUPLICATE) {
        snprintf(msg, sizeof(msg), "%s is already blacklisted.", clean);
    } else {
        ok = true;
        if (app.store->appendBlacklist(clean))
            snprintf(msg, sizeof(msg), "Added %s to the blacklist.", clean);
        else
            snprintf(msg, sizeof(msg), "Added %s for this session, but blacklist.txt could not be written.", clean);
    }

    char msgJson[900];
    jsonEscape(msg, msgJson, sizeof(msgJson));
    char body[1000];
    snprintf(body, sizeof(body), "{\"ok\":%s,\"message\":\"%s\"}", ok ? "true" : "false", msgJson);
    sendJson(c, 200, body);
}

static void handleLogout(sock_t c, const char* query)
{
    char token[128];
    if (getParam(query, "token", token, sizeof(token)))
        authEndSession(token);
    sendJson(c, 200, "{\"ok\":true}");
}

static void handleClient(sock_t c, App& app)
{
    static char req[8192];
    int n = readRequest(c, req, sizeof(req));
    if (n <= 0)
        return;

    bool isGet = (strncmp(req, "GET ", 4) == 0);
    bool isPost = (strncmp(req, "POST ", 5) == 0);
    if (!isGet && !isPost) {
        sendText(c, 404, "text/plain", "Only GET and POST are supported.");
        return;
    }

    char path[2048];
    const char* pathStart = req + (isGet ? 4 : 5);
    int len = (int)strcspn(pathStart, " \r\n");
    if (len >= (int)sizeof(path))
        len = sizeof(path) - 1;
    memcpy(path, pathStart, len);
    path[len] = '\0';

    const char* query = strchr(path, '?');
    query = (query != NULL) ? query : "";

    char route[256];
    int routeLen = (int)strcspn(path, "?");
    if (routeLen >= (int)sizeof(route))
        routeLen = sizeof(route) - 1;
    memcpy(route, path, routeLen);
    route[routeLen] = '\0';

    const char* headerEnd = strstr(req, "\r\n\r\n");
    const char* body = (headerEnd != NULL) ? headerEnd + 4 : "";

    if (isGet && (strcmp(route, "/") == 0 || strcmp(route, "/index.html") == 0))
        sendHomePage(c);
    else if (isPost && strcmp(route, "/login") == 0)
        handleLogin(c, body);
    else if (isGet && strcmp(route, "/check") == 0)
        handleCheck(c, query, app);
    else if (isGet && strcmp(route, "/history") == 0)
        handleHistory(c, query, app);
    else if (isGet && strcmp(route, "/add") == 0)
        handleAdd(c, query, app);
    else if (isGet && strcmp(route, "/logout") == 0)
        handleLogout(c, query);
    else
        sendText(c, 404, "text/plain", "Not found.");
}

int main(int argc, char* argv[])
{
    int port = (argc > 1) ? atoi(argv[1]) : 8080;

    authInit("users.db");

    Engine engine;
    data store("blacklist.txt", "history.txt");
    LoadSummary s;

    std::cout << "Loading blacklist.txt ...\n";
    if (!store.loadBlacklist(engine, s)) {
        std::cout << "Could not open blacklist.txt. Run the server from the project folder.\n";
        return 1;
    }
    std::cout << "Loaded " << s.loaded << " entries (" << s.cidrs << " CIDR ranges), "
              << s.duplicates << " duplicates, " << s.invalid << " invalid lines skipped.\n";

    MLChecker ml;
    if (ml.load("ml_url_checker/ml_weights.txt") || ml.load("ml_weights.txt"))
        std::cout << "ML model loaded (logistic regression, " << ML_FEATURES << " features).\n";
    else
        std::cout << "ML model not found (ml_url_checker/ml_weights.txt) - running without ML.\n";

    Queue queue;
    App app;
    app.engine = &engine;
    app.ml = &ml;
    app.queue = &queue;
    app.store = &store;

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cout << "WSAStartup failed.\n";
        return 1;
    }
#endif

    sock_t server = socket(AF_INET, SOCK_STREAM, 0);
    if (server == INVALID_SOCKET) {
        std::cout << "Could not create socket.\n";
        return 1;
    }

    int yes = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons((unsigned short)port);

    if (bind(server, (sockaddr*)&addr, sizeof(addr)) != 0 || listen(server, 10) != 0) {
        std::cout << "Could not use port " << port << " (is the server already running?).\n";
        return 1;
    }

    std::cout << "\nServer running. Open  http://localhost:" << port << "  in your browser.\n";
    std::cout << "Press Ctrl+C to stop.\n" << std::flush;

    while (true) {
        sock_t client = accept(server, NULL, NULL);
        if (client == INVALID_SOCKET)
            continue;
        handleClient(client, app);
        CLOSE_SOCKET(client);
    }

    return 0;
}
