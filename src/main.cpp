#include <iostream>
#include "../include/authentication_server.h"
#include "../include/ticket_granting_server.h"
#include "../include/service_server.h"

int main() {
    AuthenticationServer as;
    TicketGrantingServer tgs;
    ServiceServer ss;

    std::string username = "alice";
    std::string password = "password123";

    // Bước 1: Xác thực với Authentication Server
    std::cout << "---------------Xac thuc voi Authen Server---------------" << std::endl;
    std::string encryptedTGT = as.AuthenticateUser(username, password);
    if (encryptedTGT == "Authentication Failed") {
        std::cout << "Login Failed!" << std::endl;
        return 1;
    }
    std::cout << std::endl;

    // Bước 2: Yêu cầu vé dịch vụ từ TGS
    std::cout << "---------------Yeu cau ve dich vu tu TGS---------------" << std::endl;
    std::string serviceName = "FileServer";
    std::string encryptedServiceTicket = tgs.Generate_Service_Ticket(encryptedTGT, serviceName);
    std::cout << std::endl;
    
    // Bước 3: Truy cập dịch vụ
    std::cout << "---------------Truy cap dich vu---------------" << std::endl;
    if (ss.Validate_Service_Ticket(encryptedServiceTicket)) {
        std::cout << "Access Granted to " << serviceName << std::endl;
    } else {
        std::cout << "Access Denied!" << std::endl;
    }

    return 0;
}
