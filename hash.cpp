#include <iostream>
#include "BUT_HEADER.h"

static bool isValidUrl(const char* s)
{
    return s != NULL && s[0] != '\0' && strlen(s) < (size_t)MAX_URL;
}

LNode::LNode(const char* value)
{
    safeCopy(data, value, MAX_URL);
    next = NULL;
}

linkedlist::linkedlist()
{
    head = NULL;
    length = 0;
}

linkedlist::~linkedlist()
{
    while (head != NULL) {
        LNode* temp = head;
        head = head->next;
        delete temp;
    }
}

bool linkedlist::insert(const char* value)
{
    if (!isValidUrl(value))
        return false;

    LNode* node = new LNode(value);
    node->next = head;
    head = node;
    length++;
    return true;
}

bool linkedlist::search(const char* value)
{
    if (!isValidUrl(value))
        return false;

    LNode* cur = head;
    while (cur != NULL) {
        if (strcmp(cur->data, value) == 0)
            return true;
        cur = cur->next;
    }
    return false;
}

bool linkedlist::remove(const char* value)
{
    if (!isValidUrl(value))
        return false;

    LNode* prev = NULL;
    LNode* cur = head;

    while (cur != NULL) {
        if (strcmp(cur->data, value) == 0) {
            if (prev == NULL)
                head = cur->next;
            else
                prev->next = cur->next;

            delete cur;
            length--;
            return true;
        }
        prev = cur;
        cur = cur->next;
    }
    return false;
}

int linkedlist::getLength()
{
    return length;
}

void linkedlist::display()
{
    LNode* cur = head;
    while (cur != NULL) {
        std::cout << cur->data;
        if (cur->next != NULL)
            std::cout << " -> ";
        cur = cur->next;
    }
}

hashTable::hashTable(int size)
{
    tableSize = (size > 0) ? size : 101;
    table = new linkedlist[tableSize];
    count = 0;
}

hashTable::~hashTable()
{
    delete[] table;
}

unsigned long hashTable::hashFunction(const char* s)
{
    unsigned long hash = 5381;

    if (s == NULL)
        return hash;

    for (int i = 0; s[i] != '\0'; i++)
        hash = hash * 33 + (unsigned char)s[i];

    return hash;
}

bool hashTable::insert(const char* url)
{
    if (!isValidUrl(url))
        return false;

    unsigned long index = hashFunction(url) % (unsigned long)tableSize;

    if (table[index].search(url))
        return false;

    table[index].insert(url);
    count++;
    return true;
}

bool hashTable::search(const char* url)
{
    if (!isValidUrl(url))
        return false;

    unsigned long index = hashFunction(url) % (unsigned long)tableSize;
    return table[index].search(url);
}

bool hashTable::remove(const char* url)
{
    if (!isValidUrl(url))
        return false;

    unsigned long index = hashFunction(url) % (unsigned long)tableSize;
    if (table[index].remove(url)) {
        count--;
        return true;
    }
    return false;
}

int hashTable::size()
{
    return count;
}

double hashTable::loadFactor()
{
    return (double)count / (double)tableSize;
}

int hashTable::longestChain()
{
    int longest = 0;
    for (int i = 0; i < tableSize; i++) {
        if (table[i].getLength() > longest)
            longest = table[i].getLength();
    }
    return longest;
}

void hashTable::displayTable()
{
    std::cout << "---- Hash table: " << count << " entries, "
              << tableSize << " buckets ----\n";

    for (int i = 0; i < tableSize; i++) {
        if (table[i].getLength() > 0) {
            std::cout << "Bucket " << i << ": ";
            table[i].display();
            std::cout << "\n";
        }
    }

    std::cout << "Load factor: " << loadFactor()
              << " | Longest chain: " << longestChain() << "\n";
}
