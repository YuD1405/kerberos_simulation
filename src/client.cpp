#include <iostream>
#include "../include/client.h"

// string Client::getUserName(){
//     return username;
// }

// string Client::getPassword(){
//     return password;
// }

// string Client::getServiceTicket(){
//     return encrypted_service_ticket;
// }

// string Client::getTGT(){
//     return encrypted_TGT;
// }

// string Client::getSessionKey(){
//     return session_key;
// }

// void Client::setSessionKey(string session_key ){
//     this->session_key = session_key;
// }

// void Client::setServiceTicket(string ticket){
//     this->encrypted_service_ticket = ticket;
// }

// void Client::setTGT(string ticket){
//     this->encrypted_TGT = ticket;
// }

string Client::Request_TGT(AuthenticationServer& AS){
    cout << "[REQUEST - CLIENT] Sending authentication request for user " << username << "...\n";
    if(!AS.AuthenticateUser(username, password)){
        return "Failed: User does not exists.";
    }
    
    encrypted_TGT = AS.Generate_TGT(username, "master_key_of_quang_duy");

    if (!encrypted_TGT.empty()) {
        cout << "[INFO - CLIENT] Received TGT. Authentication successful!\n";
        return encrypted_TGT;
    } else {
        cerr << "[ERROR - CLIENT] Authentication failed.\n";
        return "Failed: Generate TGT failed.";
    }
}

string Client::UserRequest_ServiceTicket(TicketGrantingServer& TGS, const string& encrypted_TGT, const string& service_name){
    cout << "[REQUEST - CLIENT] Sending service request for user " << username << "...\n";
    if(!TGS.Validate_TGT(encrypted_TGT, "master_key_of_quang_duy")){
        return "Failed: Invalid TGT";
    }
    
    encrypted_service_ticket = TGS.Generate_Service_Ticket(service_name, "master_key_of_quang_duy");

    if (!encrypted_service_ticket.empty()) {
        cout << "[INFO - CLIENT] Client: Received Service Ticket !\n";
        return encrypted_service_ticket;
    } else {
        cerr << "[ERROR - CLIENT] Client: Generate ST failed.\n";
        return "Failed: Generate ST failed.";
    }
}

string Client::Access_Service(ServiceServer &SS, const string& service_ticket, const string& service_name){
    cout << "[ACCESS - CLIENT] Access to service: " << service_name << "...\n";
    if(!SS.Validate_Service_Ticket(service_ticket, "master_key_of_quang_duy")){
        return "Failed: Invalid Service ticket";
    }

    string granting_result = SS.Grant_Access(service_name);
    cout << "[ACCESS - CLIENT] Accessible for " + service_name << endl;
    return granting_result;
}