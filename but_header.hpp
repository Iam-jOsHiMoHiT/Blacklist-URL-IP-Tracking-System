#ifndef BUT_HEADER
#define BUT_HEADER

#include <cstring>

const int MAX_URL  = 256;
const int MAX_LINE = 300;
const int BLOOM_BITS = 262144;
const int MAX_CIDR = 4096;

enum { INPUT_INVALID = 0, INPUT_URL = 1, INPUT_IPV4 = 2, INPUT_CIDR = 3 };
enum { RESULT_INVALID = -1, RESULT_ALLOWED = 0, RESULT_BLOCKED = 1 };
enum { ADD_INVALID = 0, ADD_NEW = 1, ADD_DUPLICATE = 2, ADD_CIDR = 3 };

class QNode{

    public:
    char data[MAX_URL];
    QNode* next;

    QNode(const char* value);
};

class Queue{

    private:
    QNode* front;
    QNode* rear;

    Queue(const Queue&);
    Queue& operator=(const Queue&);

    public:
    Queue();
    ~Queue();
    bool enqueue(const char* url);
    bool dequeue(char* out);
};

class LNode{

    public:
    char data[MAX_URL];
    LNode* next;

    LNode(const char* value);
};

class linkedlist{

    private:
    LNode* head;
    int length;

    linkedlist(const linkedlist&);
    linkedlist& operator=(const linkedlist&);

    public:
    linkedlist();
    ~linkedlist();
    bool insert(const char* value);
    bool search(const char* value);
    bool remove(const char* value);
    int getLength();
    void display();
};

class hashTable{

    private:
    linkedlist* table;
    int tableSize;
    int count;

    hashTable(const hashTable&);
    hashTable& operator=(const hashTable&);

    public:
    hashTable(int size = 101);
    ~hashTable();
    unsigned long hashFunction(const char* s);
    bool insert(const char* url);
    bool search(const char* url);
    bool remove(const char* url);
    int size();
    double loadFactor();
    int longestChain();
    void displayTable(int maxBuckets = 20);
};

class BloomFilter{

    private:
    unsigned char bits[BLOOM_BITS / 8];

    unsigned int hash1(const char* url);
    unsigned int hash2(const char* url);
    unsigned int hash3(const char* url);
    void setBit(unsigned int i);
    bool getBit(unsigned int i);

    public:
    BloomFilter();
    void insert(const char* url);
    bool check(const char* url);
};

class CacheNode{

    public:
    char url[MAX_URL];
    char verdict[10];
    CacheNode* prev;
    CacheNode* next;

    CacheNode(const char* u, const char* v);
};

class LRUCache{

    private:
    int capacity;
    int currentSize;
    CacheNode* head;
    CacheNode* tail;

    LRUCache(const LRUCache&);
    LRUCache& operator=(const LRUCache&);

    void removeNode(CacheNode* node);
    void addToFront(CacheNode* node);
    CacheNode* find(const char* url);

    public:
    LRUCache(int cap = 100);
    ~LRUCache();
    bool get(const char* targetUrl, char* outVerdict);
    void put(const char* newUrl, const char* newVerdict);
    void clear();
};

class CidrList{

    private:
    unsigned int base[MAX_CIDR];
    int prefix[MAX_CIDR];
    int count;

    public:
    CidrList();
    bool add(const char* cidr);
    int match(unsigned int ip) const;
    int size() const;
};

class Engine{

    private:
    Engine(const Engine&);
    Engine& operator=(const Engine&);

    int entryCap;
    void remember(const char* clean);

    public:
    hashTable table;
    BloomFilter bloom;
    CidrList cidrs;
    LRUCache cache;

    char** entries;
    int entryCount;

    int checkedCount;
    int blockedCount;
    int cacheHits;
    int bloomSkips;

    Engine();
    ~Engine();

    int addEntry(const char* raw, char* cleanOut);

    int check(const char* raw, char* clean, char* reason, int reasonSize);
};

struct LoadSummary{
    int read;
    int loaded;
    int duplicates;
    int invalid;
    int skipped;
    int cidrs;
};

class data{

    private:
    char blacklistFile[MAX_URL];
    char historyFile[MAX_URL];

    public:
    data(const char* blacklistPath = "blacklist.txt", const char* historyPath = "history.txt");
    bool loadBlacklist(Engine& engine, LoadSummary& summary);
    bool appendBlacklist(const char* clean);
    bool saveResult(const char* url, bool blocked);
    int getHistory(char lines[][MAX_LINE], int maxLines);
};

const int ML_FEATURES = 11;
const double ML_WARN_THRESHOLD = 0.80;

class MLChecker{

    private:
    bool loaded;
    double median[ML_FEATURES];
    double mean[ML_FEATURES];
    double scale[ML_FEATURES];
    double weight[ML_FEATURES];
    double intercept;

    void extractFeatures(const char* url, double* f);

    public:
    int scored;
    int flagged;

    MLChecker();
    bool load(const char* path);

    double spamProbability(const char* rawInput);
};

int checkWithML(Engine& engine, MLChecker& ml, const char* raw,
                char* clean, char* reason, int reasonSize, double& mlSpam);

class display{

    public:
    void showMenu();
    void displayResult(const char* url, bool blocked, const char* reason, double mlSpam);
    void displayInvalid(const char* input);
    void displayHistory(char lines[][MAX_LINE], int count);
    void displayStats(int entries, int cidrCount, double loadFactor, int longestChain,
                      int checked, int blocked, int cacheHits, int bloomSkips,
                      int mlScored, int mlFlagged);
};

void safeCopy(char* dest, const char* src, int destSize);
void toLowerStr(char* s);
void trimStr(char* s);
bool isValidUrl(const char* s);
bool parseIPv4(const char* s, unsigned int& out);
int  normalizeInput(const char* raw, char* out, int outSize);
void extractHost(const char* clean, char* host, int hostSize);

#endif
