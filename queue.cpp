#include "but_header.hpp"

QNode::QNode(const char* value)
{
    safeCopy(data, value, MAX_URL);
    next = NULL;
}

Queue::Queue()
{
    front = NULL;
    rear = NULL;
    count = 0;
}

Queue::~Queue()
{
    while (front != NULL) {
        QNode* temp = front;
        front = front->next;
        delete temp;
    }
}

bool Queue::enqueue(const char* url)
{
    if (!isValidUrl(url))
        return false;

    QNode* node = new QNode(url);

    if (rear == NULL) {
        front = node;
        rear = node;
    } else {
        rear->next = node;
        rear = node;
    }
    count++;
    return true;
}

bool Queue::dequeue(char* out)
{
    if (front == NULL || out == NULL)
        return false;

    QNode* temp = front;
    safeCopy(out, temp->data, MAX_URL);
    front = front->next;

    if (front == NULL)
        rear = NULL;

    delete temp;
    count--;
    return true;
}

bool Queue::isEmpty()
{
    return front == NULL;
}

int Queue::size()
{
    return count;
}
