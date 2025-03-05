#include "../include/service_server.h"
#include "../include/encryption.h"

bool ServiceServer::Validate_Service_Ticket(const std::string& encryptedServiceTicket) {
    return encryptedServiceTicket.find("encrypted_") != std::string::npos;
}
