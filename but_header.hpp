#ifndef BUT_HEADER
#define BUT_HEADER
#include <string>
#include <vector>

//auth.cpp
class auth{

    private:
    std::string username;
    std::string password;
    int attempts;
    std::string valid_username;
    std::string valid_password;
    
    public:
    auth();  //constructor
    bool login();

};

//display.cpp

class display{

    public:
    void showMenu();
    void displayResult(std::string url, bool blocked);
    void displayHistory();

};


//queue.cpp
class QNode{

    public:
    std::string data;
    QNode* next;

    QNode(std::string value); // constructor
};

class Queue{

    QNode* front;
    QNode* rear;
    int count;

    public:
    Queue();  //constructor;
    void enqueue(std::string url);
    std::string dequeue();
    bool isEmpty();
    int size();
};

//hash.cpp
class hashTable{
    //pending
};

//linkedlist.cpp
class LNode{

    public:
    std::string data;
    LNode* next;

    LNode(std::string value);  // constructor
};

class linkedlist{
    private:
    LNode* head;

    public:
    linkedlist();  //constructor
    void insert(std::string value);
    bool search(std::string value);
};

//data.cpp
class data{

    private:
    std::string blacklistFile;
    std::string historyFile;

    public:
    data();  //constructor
    bool loadBlacklist(hashTable& table);
    bool saveResult(std::string url, bool blocked);
    std::vector<std::string> getHistory();
};

#endif