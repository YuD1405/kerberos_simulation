#ifndef CLIENT_H
#define CLIENT_H

#include <string>
using namespace std;

class Client {
public:
    string Request_TGT(const string& username, const string& password);
    string Request_Service_Ticket(const string& tgt, const string& service_name);
    string Access_Service(const string& service_ticket, const string& service_name);
};

#endif // CLIENT_H
