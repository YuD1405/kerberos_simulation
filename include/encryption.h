#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <openssl/evp.h>
#include <string>
using namespace std;

string Encrypt(const string& plaintext, const string& key);
string Decrypt(const string& ciphertext, const string& key);

#endif
