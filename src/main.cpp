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
    std::string encryptedServiceTicket = tgs.GenerateServiceTicket(encryptedTGT, serviceName);
    std::cout << std::endl;
    
    // Bước 3: Truy cập dịch vụ
    std::cout << "---------------Truy cap dich vu---------------" << std::endl;
    if (ss.ValidateServiceTicket(encryptedServiceTicket)) {
        std::cout << "Access Granted to " << serviceName << std::endl;
    } else {
        std::cout << "Access Denied!" << std::endl;
    }

    return 0;
}
