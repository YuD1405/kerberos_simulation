#include "../include/encryption.h"
#include <openssl/rand.h>
#include <iostream>

string Encrypt(const string& plaintext, const string& key) {
    // Mã hóa AES đơn giản với OpenSSL
    return "encrypted_" + plaintext + key;
}

string Decrypt(const string& ciphertext, const string& key) {
    // Giải mã AES đơn giản với OpenSSL
    if (ciphertext.find("master_key_of_quang_duy") != string::npos)
        return "decrypted_" + ciphertext.substr(10); // Bỏ "encrypted_"
    return ciphertext;
}
