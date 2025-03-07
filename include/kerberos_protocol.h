#ifndef KERBEROS_PROTOCOL_H
#define KERBEROS_PROTOCOL_H

#include <string>
#include "../include/client.h"

using namespace std;

class KerberosProtocol {
private:
    AuthenticationServer AS;
    TicketGrantingServer TGS;
    ServiceServer SS;

public:
    KerberosProtocol(AuthenticationServer& AS, TicketGrantingServer& TGS, ServiceServer& SS);
    // Gửi yêu cầu xác thực và nhận TGT
    string authenticateClient(Client& user);

    // Yêu cầu Service Ticket từ TGS để nhận Service ticket
    string requestServiceTicket(Client& user, const string& encrypted_tgt, const string& service_name);

    // Truy cập dịch vụ bằng Service Ticket
    bool accessService(Client& user, const string& encrypted_service_ticket, const string& service_name);
};

#endif // KERBEROS_PROTOCOL_H
