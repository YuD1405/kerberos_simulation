#ifndef SERVICE_SERVER_H
#define SERVICE_SERVER_H

#include <string>
using namespace std;

class ServiceServer {
public:
    bool Validate_Service_Ticket(const string& encrypted_ST, const string& kdc_master_key);
    string Grant_Access(const string& service_name);
};

#endif
