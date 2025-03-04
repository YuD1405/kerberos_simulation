#include "kerberos_service.h"
#include "encryption.h"

bool ServiceServer::ValidateServiceTicket(const std::string& encryptedServiceTicket) {
    return encryptedServiceTicket.find("encrypted_") != std::string::npos;
}
