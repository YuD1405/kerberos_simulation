#include "../include/kerberos_protocol.h"
#include "../include/encryption.h"
#include <iostream>

KerberosProtocol::KerberosProtocol(AuthenticationServer& AS, TicketGrantingServer& TGS, ServiceServer& SS){
    this->AS = AS;
    this->TGS = TGS;
    this->SS = SS;
}

 // Gửi yêu cầu xác thực và nhận TGT
 string KerberosProtocol::authenticateClient(Client& user){
    string encr_TGT = user.Request_TGT(AS);
    
    if (encr_TGT.find("Failed") != string::npos){
      return "[ERROR - KERBEROS] Authenticate user and generate TGT failed !";
    } else {
      return encr_TGT;
    }
 }

 // Yêu cầu Service Ticket từ TGS để nhận Service ticket
 string KerberosProtocol::requestServiceTicket(Client& user, const string& encrypted_tgt, const string& service_name){
    string encr_ST = user.UserRequest_ServiceTicket(TGS, encrypted_tgt, service_name);

    if (encr_ST.find("Failed") != string::npos){
      return "[ERROR - KERBEROS] Request ST failed !";
    } else {
      return encr_ST;
    }
 }

 // Truy cập dịch vụ bằng Service Ticket
 bool KerberosProtocol::accessService(Client& user, const string& encrypted_service_ticket, const string& service_name){
    string granting_res =  user.Access_Service(SS, encrypted_service_ticket, service_name);
    if (granting_res.find("Failed") != string::npos){
      return 0;
    }
    return 1;
 }