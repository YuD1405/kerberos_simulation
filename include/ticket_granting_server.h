#ifndef TICKET_GRANTING_SERVER_H
#define TICKET_GRANTING_SERVER_H

#include <string>
#include <unordered_map>

using namespace std;

class TicketGrantingServer
{
public:
    bool Validate_TGT(const string &encryptedTGT, const string &kdcMasterKey);
    string Generate_Service_Ticket(const string &username, const string &serviceName, const string &kdcMasterKey);
    bool Revoke_Service_Ticket(const string &sessionKey);
};

#endif // TICKET_GRANTING_SERVER_H
