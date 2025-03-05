#ifndef KERBEROS_PROTOCOL_H
#define KERBEROS_PROTOCOL_H

#include <string>
using namespace std;

class KerberosProtocol {
public:
    string Client_Request_TGT(const string& username, const string& password);
    string Client_Request_Service_Ticket(const string& tgt, const string& service_name);
    string Client_Access_Service(const string& service_ticket, const string& service_name);
};

#endif // KERBEROS_PROTOCOL_H
