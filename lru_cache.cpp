
#ifndef LRU_CACHE_H
#define LRU_CACHE_H

#include <unordered_map>
#include <mutex>

// 1. The Doubly Linked List Node
// We build this from scratch to prove Data Structures knowledge for the viva.
template <typename K, typename V>
struct CacheNode {
    K key;
    V value;
    CacheNode* prev;
    CacheNode* next;

    CacheNode(K k, V v) : key(k), value(v), prev(nullptr), next(nullptr) {}
};

template <typename K, typename V>
class LRUCache {
private:
    size_t capacity;
    std::unordered_map<K, CacheNode<K, V>*> cacheMap; // Hash map for O(1) lookups
    
    CacheNode<K, V>* head; // Most recently used
    CacheNode<K, V>* tail; // Least recently used
    
    mutable std::mutex mtx; // Protects the cache from thread collisions

    // Helper: Safely unlinks a node from the chain without deleting it
    void removeNode(CacheNode<K, V>* node) {
        if (node->prev != nullptr) {
            node->prev->next = node->next;
        } else {
            head = node->next;
        }

        if (node->next != nullptr) {
            node->next->prev = node->prev;
        } else {
            tail = node->prev;
        }
    }

    // Helper: Puts a node at the very front of the list
    void addToFront(CacheNode<K, V>* node) {
        node->next = head;
        node->prev = nullptr;

        if (head != nullptr) {
            head->prev = node;
        }
        head = node;

        if (tail == nullptr) {
            tail = node;
        }
    }

public:
    // Constructor sets the maximum size
    explicit LRUCache(size_t cap) : capacity(cap), head(nullptr), tail(nullptr) {}

    // Destructor clears memory to pass AddressSanitizer checks
    ~LRUCache() {
        clear();
    }

    // get(): O(1) time. Checks if the URL was recently checked.
    bool get(const K& key, V& out) {
        std::lock_guard<std::mutex> lock(mtx); // Locks the thread safely

        if (cacheMap.find(key) != cacheMap.end()) {
            CacheNode<K, V>* node = cacheMap[key];
            out = node->value;

            // Move to front because it was just used!
            removeNode(node);
            addToFront(node);
            return true;
        }
        return false;
    }

    // put(): O(1) time. Adds a new URL result, evicting the oldest if full.
    void put(const K& key, const V& value) {
        std::lock_guard<std::mutex> lock(mtx);

        // If it already exists, update its value and move to front
        if (cacheMap.find(key) != cacheMap.end()) {
            CacheNode<K, V>* node = cacheMap[key];
            node->value = value;
            removeNode(node);
            addToFront(node);
            return;
        }

        // If cache is full, delete the Least Recently Used node (the tail)
        if (cacheMap.size() >= capacity) {
            if (tail != nullptr) {
                cacheMap.erase(tail->key); // Remove from hash map
                CacheNode<K, V>* temp = tail;
                removeNode(tail);          // Remove from linked list
                delete temp;               // Free the memory
            }
        }

        // Create new node and add to the front
        CacheNode<K, V>* newNode = new CacheNode<K, V>(key, value);
        addToFront(newNode);
        cacheMap[key] = newNode;
    }

    // clear(): Wipes the cache entirely (Called when an Admin edits the blacklist)
    void clear() {
        std::lock_guard<std::mutex> lock(mtx);
        CacheNode<K, V>* current = head;
        while (current != nullptr) {
            CacheNode<K, V>* temp = current;
            current = current->next;
            delete temp;
        }
        head = nullptr;
        tail = nullptr;
        cacheMap.clear();
    }
};

#endif
