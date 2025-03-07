#include "../include/service_server.h"
#include "../include/encryption.h"
#include <iostream>

bool ServiceServer::Validate_Service_Ticket(const string& encrypted_ST, const string& kdc_master_key) {
    string decrypt_ST = Decrypt(encrypted_ST, kdc_master_key);

    cout << "[INFO - ST] Server is checking ticket... " << endl;
    if(decrypt_ST.find("decrypted") != string::npos) { // thêm check service có tồn tại không
        cout << "[INFO - ST] Valid ST!\n";
        return 1;
    } else {
        cerr << "[ERROR - ST] Invalid ST!" << endl;
        return 0;
    }
}

string ServiceServer::Grant_Access(const string& service_name){
    return "[INFO - ST] Access Granted to " + service_name;
}
