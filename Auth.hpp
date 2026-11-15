#ifndef AUTH_HPP
#define AUTH_HPP

void authInit(const char* usersFile);

bool authLogin(const char* user, const char* pass, char* role, int roleSize, char* msg, int msgSize);

bool authRegister(const char* byUser, const char* byRole, const char* newUser,
                  const char* newPass, const char* newRole, char* msg, int msgSize);

bool authCanEdit(const char* role);

bool authStartSession(const char* user, const char* role, char* token, int tokenSize);
bool authCheckSession(const char* token, char* user, int userSize, char* role, int roleSize);
void authEndSession(const char* token);

#endif
