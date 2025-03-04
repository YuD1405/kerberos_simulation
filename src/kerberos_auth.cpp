#include "kerberos_auth.h"
#include "encryption.h"
#include <iostream>

AuthenticationServer::AuthenticationServer() {
    // Giả lập database người dùng (username -> password)
    userDB["alice"] = "password123";
}

std::string AuthenticationServer::AuthenticateUser(const std::string& username, const std::string& password) {
    if (userDB.find(username) != userDB.end() && userDB[username] == password) {
        std::string sessionKey = "session_key_" + username;
        std::cout << "Session key (Authen): " << sessionKey << std::endl;
        std::cout << "Encrypt Session key (Authen): " << std::endl;
        return Encrypt(sessionKey, "KDC_master_key");
    }
    return "Authentication Failed";
}
