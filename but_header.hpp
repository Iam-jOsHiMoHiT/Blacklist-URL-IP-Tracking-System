#ifndef BUT_HEADER
#define BUT_HEADER

#include <cstring>

const int MAX_URL  = 256;
const int MAX_LINE = 300;

void safeCopy(char* dest, const char* src, int destSize);
void toLowerStr(char* s);
void trimStr(char* s);

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
    int count;

    Queue(const Queue&);
    Queue& operator=(const Queue&);

    public:
    Queue();
    ~Queue();
    bool enqueue(const char* url);
    bool dequeue(char* out);
    bool isEmpty();
    int size();
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
    void displayTable();
};

class data{

    private:
    char blacklistFile[MAX_URL];
    char historyFile[MAX_URL];

    public:
    data();
    int loadBlacklist(hashTable& table);
    bool saveResult(const char* url, bool blocked);
    int getHistory(char lines[][MAX_LINE], int maxLines);
};

class display{

    public:
    void showMenu();
    void displayResult(const char* url, bool blocked);
    void displayHistory(char lines[][MAX_LINE], int count);

};

#endif
