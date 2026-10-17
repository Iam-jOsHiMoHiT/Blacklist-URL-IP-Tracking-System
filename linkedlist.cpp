
#include <iostream>
#include "but_header.hpp"

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
