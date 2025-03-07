#include "../include/ticket_granting_server.h"
#include "../include/encryption.h"
#include <iostream>

bool TicketGrantingServer::Validate_TGT(const string& encryptedTGT, const string& kdc_master_key){
    string decrypt_TGT = Decrypt(encryptedTGT, kdc_master_key);

    cout << "[INFO - TGT] Server is checking ticket... " << endl;
    if(decrypt_TGT.find("decrypted") != string::npos) {
        cout << "[INFO - TGT] Valid TGT!\n";
        return 1;
    } else {
        cerr << "[ERROR - TGT] Invalid TGT!" << endl;
        return 0;
    }
}

string TicketGrantingServer::Generate_Service_Ticket(const string& serviceName, const string& kdc_master_key) {
    string newSessionKey = "session_key_" + serviceName;
    cout << "[INFO - TGT] Session key (Service): " << newSessionKey << endl;
    return Encrypt(newSessionKey, kdc_master_key);
}
