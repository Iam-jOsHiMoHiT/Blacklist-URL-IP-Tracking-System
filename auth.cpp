#include "but_header.hpp"
#include <iostream>

auth::auth()
{
    attempt_counter = 0;
    valid_username = "admin";
    valid_password = "1234";
}

bool auth::login()
{
    while (attempt_counter < 3)
    {
        std::cout << "Enter username: ";
        std::cin >> username;

        std::cout << "Enter password: ";
        std::cin >> password;

        attempt_counter++;

        if (username == valid_username && password == valid_password)
        {
            std::cout << "Login successful. Welcome, " << username << "!\n";
            return true;
        }

        int attempts_left = 3 - attempt_counter;
        if (attempts_left > 0)
            std::cout << "X Wrong credentials. Attempts left: "
                      << attempts_left << "\n";
        else
            std::cout << "X Wrong credentials. No attempts left.\n";
    }

    return false;
}
