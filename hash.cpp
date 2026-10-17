#include <iostream>
#include "but_header.hpp"

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
