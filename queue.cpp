#include "but_header.hpp"
#include <iostream>

QNode::QNode(std::string value)
{
    data = value;
    next = nullptr;
}

Queue::Queue()
{
    front = nullptr;
    rear = nullptr;
    count = 0;
}

bool Queue::isEmpty()
{
    return front == nullptr;
}

void Queue::enqueue(std::string url)
{
    QNode* newNode = new QNode(url);

    if (isEmpty()) {
        front = newNode;
        rear = newNode;
    } else {
        rear->next = newNode;
        rear = newNode;
    }

    count++;
}

std::string Queue::dequeue()
{
    if (isEmpty()) {
        std::cout << "Queue is empty!\n";
        return "";
    }

    QNode* temp = front;
    std::string result = temp->data;

    front = front->next;
    if (front == nullptr) {
        rear = nullptr;
    }

    delete temp;
    count--;

    return result;
}

int Queue::size()
{
    return count;
}