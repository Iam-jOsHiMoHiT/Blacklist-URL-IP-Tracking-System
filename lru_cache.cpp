#include <cstring>
#include "but_header.hpp"

CacheNode::CacheNode(const char* u, const char* v)
{
    safeCopy(url, u, MAX_URL);
    safeCopy(verdict, v, 10);
    prev = NULL;
    next = NULL;
}

LRUCache::LRUCache(int cap)
{
    capacity = (cap > 0) ? cap : 1;
    currentSize = 0;
    head = NULL;
    tail = NULL;
}

LRUCache::~LRUCache()
{
    clear();
}

void LRUCache::clear()
{
    while (head != NULL) {
        CacheNode* temp = head;
        head = head->next;
        delete temp;
    }
    tail = NULL;
    currentSize = 0;
}

void LRUCache::removeNode(CacheNode* node)
{
    if (node->prev != NULL)
        node->prev->next = node->next;
    else
        head = node->next;

    if (node->next != NULL)
        node->next->prev = node->prev;
    else
        tail = node->prev;
}

void LRUCache::addToFront(CacheNode* node)
{
    node->next = head;
    node->prev = NULL;

    if (head != NULL)
        head->prev = node;
    head = node;

    if (tail == NULL)
        tail = node;
}

CacheNode* LRUCache::find(const char* url)
{
    CacheNode* cur = head;
    while (cur != NULL) {
        if (strcmp(cur->url, url) == 0)
            return cur;
        cur = cur->next;
    }
    return NULL;
}

bool LRUCache::get(const char* targetUrl, char* outVerdict)
{
    CacheNode* node = find(targetUrl);
    if (node == NULL)
        return false;

    safeCopy(outVerdict, node->verdict, 10);
    removeNode(node);
    addToFront(node);
    return true;
}

void LRUCache::put(const char* newUrl, const char* newVerdict)
{

    CacheNode* existing = find(newUrl);
    if (existing != NULL) {
        safeCopy(existing->verdict, newVerdict, 10);
        removeNode(existing);
        addToFront(existing);
        return;
    }

    if (currentSize >= capacity && tail != NULL) {
        CacheNode* temp = tail;
        removeNode(tail);
        delete temp;
        currentSize--;
    }

    CacheNode* newNode = new CacheNode(newUrl, newVerdict);
    addToFront(newNode);
    currentSize++;
}
