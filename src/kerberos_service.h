#ifndef KERBEROS_SERVICE_H
#define KERBEROS_SERVICE_H

#include <string>

class ServiceServer {
public:
    bool ValidateServiceTicket(const std::string& encryptedServiceTicket);
};

#endif
