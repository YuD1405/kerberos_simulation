#ifndef KERBEROS_TGS_H
#define KERBEROS_TGS_H

#include <string>

class TicketGrantingServer {
public:
    std::string GenerateServiceTicket(const std::string& encryptedTGT, const std::string& serviceName);
};

#endif
