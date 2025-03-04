#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <openssl/evp.h>
#include <string>

std::string Encrypt(const std::string& plaintext, const std::string& key);
std::string Decrypt(const std::string& ciphertext, const std::string& key);

#endif
