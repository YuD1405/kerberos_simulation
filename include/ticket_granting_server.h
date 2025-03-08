#ifndef TICKET_GRANTING_SERVER_H
#define TICKET_GRANTING_SERVER_H

#include <string>
using namespace std;

class TicketGrantingServer {
public:
    bool Validate_TGT(const string& encryptedTGT, const string& kdc_master_key);
    string Generate_Service_Ticket(const string& serviceName, const string& kdc_master_key);
};

#endif
