#include "../include/ticket_granting_server.h"
#include "../include/encryption.h"
#include <iostream>

std::string TicketGrantingServer::Generate_Service_Ticket(const std::string& encryptedTGT, const std::string& serviceName) {
    if (encryptedTGT.find("encrypted_") != std::string::npos) {
        std::string newSessionKey = "session_key_" + serviceName;
        std::cout << "Session key (Service): " << newSessionKey << std::endl;
        std::cout << "Encrypt Session key (Service): " << std::endl;
        return Encrypt(newSessionKey, "KDC_master_key");
    }
    return "Invalid TGT";
}
