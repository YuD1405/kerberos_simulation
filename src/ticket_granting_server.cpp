#include "../include/ticket_granting_server.h"
#include "../include/encryption.h"
#include <iostream>
#include <fstream>
#include <ctime>
#include <random>

using namespace std;

namespace
{
    const string LOG_FILE = "service_ticket_log.txt";

    void Ensure_Log_File_Exists()
    {
        ofstream logFile(LOG_FILE, ios::app);
        if (!logFile)
        {
            cerr << "[ERROR - TGT] Unable to create log file." << endl;
        }
        logFile.close();
    }

    string Convert_Timestamp_To_Local_Time(time_t timestamp)
    {
        struct tm timeinfo;
        localtime_s(&timeinfo, &timestamp);
        char buffer[80];
        strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", &timeinfo);
        return string(buffer);
    }
}

struct ServiceTicketInfo
{
    string username;
    string serviceName;
    time_t issuedTime;
    time_t expiryTime;
};

unordered_map<string, ServiceTicketInfo> serviceTicketLog;

void Log_Service_Ticket(const ServiceTicketInfo &ticket, const string &sessionKey)
{
    Ensure_Log_File_Exists();
    ofstream logFile(LOG_FILE, ios::app);
    if (logFile.is_open())
    {
        logFile << "Username: " << ticket.username
                << ", Service: " << ticket.serviceName
                << ", Issued: " << Convert_Timestamp_To_Local_Time(ticket.issuedTime)
                << ", Expiry: " << Convert_Timestamp_To_Local_Time(ticket.expiryTime)
                << ", SessionKey: " << sessionKey << endl;
        logFile.close();
    }
    else
    {
        cerr << "[ERROR - TGT] Unable to open log file." << endl;
    }
}

string Generate_Random_Key(size_t length)
{
    static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> distrib(0, sizeof(charset) - 2);
    string key;
    for (size_t i = 0; i < length; i++)
    {
        key += charset[distrib(gen)];
    }
    return key;
}

bool TicketGrantingServer::Validate_TGT(const string &encryptedTGT, const string &kdcMasterKey)
{
    string decryptTGT = Decrypt(encryptedTGT, kdcMasterKey);
    cout << "[INFO - TGT] Checking ticket... " << endl;
    if (decryptTGT.find("decrypted") != string::npos)
    {
        cout << "[INFO - TGT] Valid TGT!\n";
        return true;
    }
    else
    {
        cerr << "[ERROR - TGT] Invalid TGT!" << endl;
        return false;
    }
}

string TicketGrantingServer::Generate_Service_Ticket(const string &username, const string &serviceName, const string &kdcMasterKey)
{
    string sessionKey = Generate_Random_Key(16);
    time_t issuedTime = time(nullptr);
    time_t expiryTime = issuedTime + 3600; // Hết hạn sau 1 giờ

    ServiceTicketInfo ticketInfo = {username, serviceName, issuedTime, expiryTime};
    serviceTicketLog[sessionKey] = ticketInfo;

    Log_Service_Ticket(ticketInfo, sessionKey);

    string ticketData = username + ":" + serviceName + ":" + sessionKey + ":" + to_string(issuedTime) + ":" + to_string(expiryTime);
    cout << "[INFO - TGT] Generated Service Ticket for " << username << " to access " << serviceName << "\n";
    cout << "[INFO - TGT] Session Key: " << sessionKey << "\n";
    return Encrypt(ticketData, kdcMasterKey);
}

bool TicketGrantingServer::Revoke_Service_Ticket(const string &sessionKey)
{
    if (serviceTicketLog.erase(sessionKey))
    {
        cout << "[INFO - TGT] Revoked Service Ticket with session key: " << sessionKey << "\n";
        return true;
    }
    cerr << "[ERROR - TGT] Service Ticket not found for revocation." << endl;
    return false;
}
