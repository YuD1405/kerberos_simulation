#ifndef TICKET_GRANTING_SERVER_H
#define TICKET_GRANTING_SERVER_H

#include <string>
using namespace std;

class TicketGrantingServer {
public:
    string Validate_TGT(const string& tgt);
    string Generate_Service_Ticket(const string& encryptedTGT, const string& serviceName);
};

#endif
