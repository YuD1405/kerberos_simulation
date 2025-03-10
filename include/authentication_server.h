#ifndef AUTHENTICATION_SERVER_H
#define AUTHENTICATION_SERVER_H

#include <string>
#include <unordered_map>
using namespace std;

class AuthenticationServer {
public:
    AuthenticationServer(); // Demo khởi tạo DB
    bool AuthenticateUser(const string& username, const string& password); // Xác thực người dùng
    string Generate_TGT(const string& username, const string& kdc_master_key); // Cấp ticket TGT

private:
    unordered_map<string, string> userDB;
};

#endif
