#include <iostream>
#include "kerberos_auth.h"
#include "kerberos_tgs.h"
#include "kerberos_service.h"

int main() {
    AuthenticationServer as;
    TicketGrantingServer tgs;
    ServiceServer ss;

    std::string username = "alice";
    std::string password = "password123";

    // Bước 1: Xác thực với Authentication Server
    std::string encryptedTGT = as.AuthenticateUser(username, password);
    if (encryptedTGT == "Authentication Failed") {
        std::cout << "Login Failed!" << std::endl;
        return 1;
    }

    // Bước 2: Yêu cầu vé dịch vụ từ TGS
    std::string serviceName = "FileServer";
    std::string encryptedServiceTicket = tgs.GenerateServiceTicket(encryptedTGT, serviceName);

    // Bước 3: Truy cập dịch vụ
    if (ss.ValidateServiceTicket(encryptedServiceTicket)) {
        std::cout << "Access Granted to " << serviceName << std::endl;
    } else {
        std::cout << "Access Denied!" << std::endl;
    }

    return 0;
}
