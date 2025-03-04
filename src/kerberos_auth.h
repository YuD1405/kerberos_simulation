#ifndef KERBEROS_AUTH_H
#define KERBEROS_AUTH_H

#include <string>
#include <unordered_map>

class AuthenticationServer {
public:
    AuthenticationServer();
    std::string AuthenticateUser(const std::string& username, const std::string& password);

private:
    std::unordered_map<std::string, std::string> userDB;
};

#endif
