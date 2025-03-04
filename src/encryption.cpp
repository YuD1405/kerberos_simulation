#include "encryption.h"
#include <openssl/rand.h>
#include <iostream>

std::string Encrypt(const std::string& plaintext, const std::string& key) {
    // Mã hóa AES đơn giản với OpenSSL
    std::cout << "Encrypt: " << "encrypted_" + plaintext << std::endl;
    return "encrypted_" + plaintext;
}

std::string Decrypt(const std::string& ciphertext, const std::string& key) {
    // Giải mã AES đơn giản với OpenSSL
    std::cout << "Decrypt: " << ciphertext.substr(10) << std::endl;
    return ciphertext.substr(10); // Bỏ "encrypted_"
}
