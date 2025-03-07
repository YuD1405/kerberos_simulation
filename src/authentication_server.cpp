#include <cstdint>
#include <ctime>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <chrono>
#include <cstring>
#include <random>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md4.h>
#include <openssl/hmac.h>

// Constants for Kerberos protocol
enum class KrbMessageType : int32_t {
    AS_REQ = 10,
    AS_REP = 11,
    TGS_REQ = 12,
    TGS_REP = 13,
    AP_REQ = 14,
    AP_REP = 15,
    ERROR = 30
};

enum class PrincipalNameType : int32_t {
    UNKNOWN = 0,
    PRINCIPAL = 1,  // user@REALM
    SRV_INST = 2,   // service/hostname@REALM
    SRV_HST = 3,    // service/hostname@REALM (unused)
    SRV_XHST = 4,   // service/host-with-port@REALM
    UID = 5,        // uid@REALM
    X500_PRINCIPAL = 6  // DN from X.509 cert
};

enum class EncryptionType : int32_t {
    DES_CBC_CRC = 1,
    DES_CBC_MD4 = 2,
    DES_CBC_MD5 = 3,
    DES3_CBC_SHA1 = 16,
    AES128_CTS_HMAC_SHA1 = 17,
    AES256_CTS_HMAC_SHA1 = 18,
    RC4_HMAC = 23
};

enum class PaDataType : int32_t {
    NONE = 0,
    TGS_REQ = 1,
    ENC_TIMESTAMP = 2,
    PW_SALT = 3,
    ENC_UNIX_TIME = 5,
    ENC_SANDIA_SECUREID = 6,
    ETYPE_INFO = 11,
    ETYPE_INFO2 = 19,
    PK_AS_REQ = 14,
    PK_AS_REP = 15
};

// Utility functions for byte operations
class ByteBuffer {
private:
    std::vector<uint8_t> buffer;
    size_t readPos = 0;

public:
    ByteBuffer() = default;
    ByteBuffer(const std::vector<uint8_t>& data) : buffer(data) {}

    // Write functions
    void writeInt32(int32_t value) {
        buffer.push_back((value >> 24) & 0xFF);
        buffer.push_back((value >> 16) & 0xFF);
        buffer.push_back((value >> 8) & 0xFF);
        buffer.push_back(value & 0xFF);
    }

    void writeDouble(double value) {
        uint64_t bits;
        memcpy(&bits, &value, sizeof(double));
        
        for (int i = 7; i >= 0; i--) {
            buffer.push_back((bits >> (i * 8)) & 0xFF);
        }
    }

    void writeString(const std::string& str) {
        writeInt32(static_cast<int32_t>(str.size()));
        for (char c : str) {
            buffer.push_back(static_cast<uint8_t>(c));
        }
    }

    void writeBytes(const std::vector<uint8_t>& bytes) {
        writeInt32(static_cast<int32_t>(bytes.size()));
        buffer.insert(buffer.end(), bytes.begin(), bytes.end());
    }

    void writeRawBytes(const std::vector<uint8_t>& bytes) {
        buffer.insert(buffer.end(), bytes.begin(), bytes.end());
    }

    // Read functions
    int32_t readInt32() {
        if (readPos + 4 > buffer.size()) {
            throw std::runtime_error("Buffer underflow while reading int32");
        }
        
        int32_t value = (buffer[readPos] << 24) |
                        (buffer[readPos + 1] << 16) |
                        (buffer[readPos + 2] << 8) |
                        buffer[readPos + 3];
        readPos += 4;
        return value;
    }

    double readDouble() {
        if (readPos + 8 > buffer.size()) {
            throw std::runtime_error("Buffer underflow while reading double");
        }
        
        uint64_t bits = 0;
        for (int i = 0; i < 8; i++) {
            bits = (bits << 8) | buffer[readPos + i];
        }
        
        double value;
        memcpy(&value, &bits, sizeof(double));
        readPos += 8;
        return value;
    }

    std::string readString() {
        int32_t length = readInt32();
        if (readPos + length > buffer.size()) {
            throw std::runtime_error("Buffer underflow while reading string");
        }
        
        std::string result(buffer.begin() + readPos, buffer.begin() + readPos + length);
        readPos += length;
        return result;
    }

    std::vector<uint8_t> readBytes() {
        int32_t length = readInt32();
        if (readPos + length > buffer.size()) {
            throw std::runtime_error("Buffer underflow while reading bytes");
        }
        
        std::vector<uint8_t> result(buffer.begin() + readPos, buffer.begin() + readPos + length);
        readPos += length;
        return result;
    }

    std::vector<uint8_t> readRawBytes(size_t length) {
        if (readPos + length > buffer.size()) {
            throw std::runtime_error("Buffer underflow while reading raw bytes");
        }
        
        std::vector<uint8_t> result(buffer.begin() + readPos, buffer.begin() + readPos + length);
        readPos += length;
        return result;
    }

    const std::vector<uint8_t>& getBuffer() const {
        return buffer;
    }

    size_t getRemainingBytes() const {
        return buffer.size() - readPos;
    }

    void reset() {
        readPos = 0;
    }
};

// KerberosTime class
class KerberosTime {
private:
    std::chrono::system_clock::time_point timestamp;

public:
    KerberosTime() : timestamp(std::chrono::system_clock::now()) {}
    
    explicit KerberosTime(const std::chrono::system_clock::time_point& time) : timestamp(time) {}
    
    explicit KerberosTime(time_t time) {
        timestamp = std::chrono::system_clock::from_time_t(time);
    }

    static KerberosTime now() {
        return KerberosTime(std::chrono::system_clock::now());
    }

    std::vector<uint8_t> toBytes() const {
        ByteBuffer buffer;
        auto duration = timestamp.time_since_epoch();
        double seconds = std::chrono::duration<double>(duration).count();
        buffer.writeDouble(seconds);
        return buffer.getBuffer();
    }

    static KerberosTime fromBytes(const std::vector<uint8_t>& data) {
        ByteBuffer buffer(data);
        double seconds = buffer.readDouble();
        auto duration = std::chrono::duration<double>(seconds);
        auto timePoint = std::chrono::system_clock::time_point(
            std::chrono::duration_cast<std::chrono::system_clock::duration>(duration));
        return KerberosTime(timePoint);
    }

    std::string toString() const {
        auto time_t_val = std::chrono::system_clock::to_time_t(timestamp);
        struct tm timeinfo;
        
        #ifdef _WIN32
        localtime_s(&timeinfo, &time_t_val);
        #else
        localtime_r(&time_t_val, &timeinfo);
        #endif
        
        char buffer[20];
        strftime(buffer, sizeof(buffer), "%Y%m%d%H%M%SZ", &timeinfo);
        return std::string(buffer);
    }

    std::chrono::system_clock::time_point getTimestamp() const {
        return timestamp;
    }
};

// Cryptographic Functions
class KerberosCrypto {
public:
    static std::vector<uint8_t> stringToKey(const std::string& password, const std::string& salt, 
                                           EncryptionType encryptionType) {
        std::vector<uint8_t> passwordBytes(password.begin(), password.end());
        std::vector<uint8_t> saltBytes(salt.begin(), salt.end());
        
        if (encryptionType == EncryptionType::AES256_CTS_HMAC_SHA1) {
            // PBKDF2 with HMAC-SHA1, iteration count 4096
            return pbkdf2_hmac_sha1(passwordBytes, saltBytes, 4096, 32);
        } 
        else if (encryptionType == EncryptionType::AES128_CTS_HMAC_SHA1) {
            return pbkdf2_hmac_sha1(passwordBytes, saltBytes, 4096, 16);
        } 
        else if (encryptionType == EncryptionType::RC4_HMAC) {
            // RC4 uses MD4 hash of UTF-16-LE encoded password
            return md4_hash_utf16le(password);
        } 
        else {
            throw std::runtime_error("Unsupported encryption type");
        }
    }

    static std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, 
                                       const std::vector<uint8_t>& key, 
                                       EncryptionType encryptionType) {
        // This is a placeholder. In a real implementation, you would:
        // 1. Generate confounder (random bytes)
        // 2. Add padding
        // 3. Encrypt with the specified algorithm
        // 4. Calculate checksum
        // 5. Package the result
        
        // For demonstration, we'll just use a simple XOR with key (NOT SECURE!)
        std::vector<uint8_t> confounder = randomBytes(16);
        std::vector<uint8_t> result = confounder;
        
        for (size_t i = 0; i < data.size(); i++) {
            // Simple XOR with key bytes (cycled if needed)
            result.push_back(data[i] ^ key[i % key.size()]);
        }
        
        // Add a mock checksum
        std::vector<uint8_t> checksum = sha1Hash(result).substr(0, 16);
        result.insert(result.end(), checksum.begin(), checksum.end());
        
        return result;
    }

    static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, 
                                       const std::vector<uint8_t>& key, 
                                       EncryptionType encryptionType) {
        // This is a placeholder. In a real implementation, you would:
        // 1. Verify checksum
        // 2. Decrypt with the specified algorithm
        // 3. Remove confounder and padding
        
        // For demonstration, assuming the same simple XOR as encrypt
        // Skip 16-byte confounder and 16-byte checksum at the end
        std::vector<uint8_t> ciphertext(data.begin() + 16, data.end() - 16);
        std::vector<uint8_t> result;
        
        for (size_t i = 0; i < ciphertext.size(); i++) {
            // Simple XOR with key bytes (cycled if needed)
            result.push_back(ciphertext[i] ^ key[i % key.size()]);
        }
        
        return result;
    }

private:
    // PBKDF2 with HMAC-SHA1
    static std::vector<uint8_t> pbkdf2_hmac_sha1(const std::vector<uint8_t>& password, 
                                                const std::vector<uint8_t>& salt, 
                                                int iterations, int keyLen) {
        std::vector<uint8_t> key(keyLen, 0);
        
        // Note: In a real implementation, you would use OpenSSL's PKCS5_PBKDF2_HMAC function
        // This is a simplified version for demonstration
        unsigned char* result = PKCS5_PBKDF2_HMAC(
            reinterpret_cast<const char*>(password.data()), password.size(),
            salt.data(), salt.size(),
            iterations,
            EVP_sha1(),
            keyLen, key.data()
        );
        
        if (result == nullptr) {
            throw std::runtime_error("PBKDF2 failed");
        }
        
        return key;
    }

    // MD4 hash of UTF-16LE encoded string
    static std::vector<uint8_t> md4_hash_utf16le(const std::string& str) {
        // Convert to UTF-16LE
        std::vector<uint8_t> utf16le;
        for (char c : str) {
            utf16le.push_back(static_cast<uint8_t>(c));
            utf16le.push_back(0);  // Little-endian: low byte first, high byte (0) second
        }
        
        // Calculate MD4 hash
        std::vector<uint8_t> hash(MD4_DIGEST_LENGTH);
        MD4_CTX ctx;
        MD4_Init(&ctx);
        MD4_Update(&ctx, utf16le.data(), utf16le.size());
        MD4_Final(hash.data(), &ctx);
        
        return hash;
    }

    static std::vector<uint8_t> randomBytes(size_t count) {
        std::vector<uint8_t> bytes(count);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> distrib(0, 255);
        
        for (size_t i = 0; i < count; i++) {
            bytes[i] = static_cast<uint8_t>(distrib(gen));
        }
        
        return bytes;
    }

    static std::vector<uint8_t> sha1Hash(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> hash(SHA_DIGEST_LENGTH);
        SHA1(data.data(), data.size(), hash.data());
        return hash;
    }
};

// Kerberos Message Structures
class PrincipalName {
public:
    int32_t nameType;
    std::vector<std::string> nameString;
    
    PrincipalName() = default;
    
    PrincipalName(int32_t type, const std::vector<std::string>& names)
        : nameType(type), nameString(names) {}
    
    std::vector<uint8_t> toBytes() const {
        ByteBuffer buffer;
        buffer.writeInt32(nameType);
        buffer.writeInt32(static_cast<int32_t>(nameString.size()));
        
        for (const auto& name : nameString) {
            buffer.writeString(name);
        }
        
        return buffer.getBuffer();
    }
    
    static std::pair<PrincipalName, ByteBuffer> fromBytes(const ByteBuffer& buffer) {
        ByteBuffer newBuffer = buffer;
        
        int32_t nameType = newBuffer.readInt32();
        int32_t nameCount = newBuffer.readInt32();
        
        std::vector<std::string> nameString;
        for (int i = 0; i < nameCount; i++) {
            nameString.push_back(newBuffer.readString());
        }
        
        return {PrincipalName(nameType, nameString), newBuffer};
    }
    
    std::string toString() const {
        std::string result;
        for (size_t i = 0; i < nameString.size(); i++) {
            if (i > 0) result += "/";
            result += nameString[i];
        }
        return result;
    }
};

class EncryptedData {
public:
    int32_t etype;
    std::optional<int32_t> kvno;
    std::vector<uint8_t> cipher;
    
    EncryptedData() = default;
    
    EncryptedData(int32_t etype, std::optional<int32_t> kvno, const std::vector<uint8_t>& cipher)
        : etype(etype), kvno(kvno), cipher(cipher) {}
    
    std::vector<uint8_t> toBytes() const {
        ByteBuffer buffer;
        buffer.writeInt32(etype);
        
        if (kvno.has_value()) {
            buffer.writeInt32(1);  // Has KVNo
            buffer.writeInt32(*kvno);
        } else {
            buffer.writeInt32(0);  // No KVNo
        }
        
        buffer.writeBytes(cipher);
        return buffer.getBuffer();
    }
    
    static std::pair<EncryptedData, ByteBuffer> fromBytes(const ByteBuffer& buffer) {
        ByteBuffer newBuffer = buffer;
        
        int32_t etype = newBuffer.readInt32();
        int32_t hasKvno = newBuffer.readInt32();
        
        std::optional<int32_t> kvno;
        if (hasKvno) {
            kvno = newBuffer.readInt32();
        }
        
        std::vector<uint8_t> cipher = newBuffer.readBytes();
        
        return {EncryptedData(etype, kvno, cipher), newBuffer};
    }
};

class PaData {
public:
    int32_t padataType;
    std::vector<uint8_t> padataValue;
    
    PaData() = default;
    
    PaData(int32_t type, const std::vector<uint8_t>& value)
        : padataType(type), padataValue(value) {}
    
    std::vector<uint8_t> toBytes() const {
        ByteBuffer buffer;
        buffer.writeInt32(padataType);
        buffer.writeBytes(padataValue);
        return buffer.getBuffer();
    }
    
    static std::pair<PaData, ByteBuffer> fromBytes(const ByteBuffer& buffer) {
        ByteBuffer newBuffer = buffer;
        
        int32_t padataType = newBuffer.readInt32();
        std::vector<uint8_t> padataValue = newBuffer.readBytes();
        
        return {PaData(padataType, padataValue), newBuffer};
    }
};

class KdcOptions {
public:
    int32_t flags = 0;
    
    // Constants for flag bits
    static const int32_t FORWARDABLE = 1 << 1;
    static const int32_t FORWARDED = 1 << 2;
    static const int32_t PROXIABLE = 1 << 3;
    static const int32_t PROXY = 1 << 4;
    static const int32_t ALLOW_POSTDATE = 1 << 5;
    static const int32_t POSTDATED = 1 << 6;
    static const int32_t RENEWABLE = 1 << 8;
    
    KdcOptions() = default;
    explicit KdcOptions(int32_t flags) : flags(flags) {}
    
    std::vector<uint8_t> toBytes() const {
        ByteBuffer buffer;
        buffer.writeInt32(flags);
        return buffer.getBuffer();
    }
    
    static std::pair<KdcOptions, ByteBuffer> fromBytes(const ByteBuffer& buffer) {
        ByteBuffer newBuffer = buffer;
        int32_t flags = newBuffer.readInt32();
        return {KdcOptions(flags), newBuffer};
    }
    
    bool isSet(int32_t flag) const {
        return (flags & flag) != 0;
    }
};

class KdcReqBody {
public:
    KdcOptions kdcOptions;
    std::optional<PrincipalName> cname;
    std::string realm;
    std::optional<PrincipalName> sname;
    std::optional<KerberosTime> fromTime;
    KerberosTime tillTime;
    std::optional<KerberosTime> rtime;
    int32_t nonce;
    std::vector<int32_t> etypes;
    // For simplicity, we'll skip addresses, authorization_data, and additional_tickets
    
    KdcReqBody() = default;
    
    std::vector<uint8_t> toBytes() const {
        ByteBuffer buffer;
        
        // kdcOptions
        buffer.writeRawBytes(kdcOptions.toBytes());
        
        // cname (optional)
        if (cname.has_value()) {
            buffer.writeInt32(1);  // Has cname
            buffer.writeRawBytes(cname->toBytes());
        } else {
            buffer.writeInt32(0);  // No cname
        }
        
        // realm
        buffer.writeString(realm);
        
        // sname (optional)
        if (sname.has_value()) {
            buffer.writeInt32(1);  // Has sname
            buffer.writeRawBytes(sname->toBytes());
        } else {
            buffer.writeInt32(0);  // No sname
        }
        
        // fromTime (optional)
        if (fromTime.has_value()) {
            buffer.writeInt32(1);  // Has fromTime
            buffer.writeRawBytes(fromTime->toBytes());
        } else {
            buffer.writeInt32(0);  // No fromTime
        }
        
        // tillTime
        buffer.writeRawBytes(tillTime.toBytes());
        
        // rtime (optional)
        if (rtime.has_value()) {
            buffer.writeInt32(1);  // Has rtime
            buffer.writeRawBytes(rtime->toBytes());
        } else {
            buffer.writeInt32(0);  // No rtime
        }
        
        // nonce
        buffer.writeInt32(nonce);
        
        // etypes
        buffer.writeInt32(static_cast<int32_t>(etypes.size()));
        for (int32_t etype : etypes) {
            buffer.writeInt32(etype);
        }
        
        // For simplicity, we'll skip addresses, authorization_data, and additional_tickets
        buffer.writeInt32(0);  // No addresses
        buffer.writeInt32(0);  // No authorization_data
        buffer.writeInt32(0);  // No additional_tickets
        
        return buffer.getBuffer();
    }
    
    static std::pair<KdcReqBody, ByteBuffer> fromBytes(const ByteBuffer& buffer) {
        ByteBuffer newBuffer = buffer;
        KdcReqBody body;
        
        // kdcOptions
        auto [kdcOptions, buffer1] = KdcOptions::fromBytes(newBuffer);
        body.kdcOptions = kdcOptions;
        newBuffer = buffer1;
        
        // cname (optional)
        int32_t hasCname = newBuffer.readInt32();
        if (hasCname) {
            auto [cname, buffer2] = PrincipalName::fromBytes(newBuffer);
            body.cname = cname;
            newBuffer = buffer2;
        }
        
        // realm
        body.realm = newBuffer.readString();
        
        // sname (optional)
        int32_t hasSname = newBuffer.readInt32();
        if (hasSname) {
            auto [sname, buffer3] = PrincipalName::fromBytes(newBuffer);
            body.sname = sname;
            newBuffer = buffer3;
        }
        
        // fromTime (optional)
        int32_t hasFromTime = newBuffer.readInt32();
        if (hasFromTime) {
            std::vector<uint8_t> timeBytes = newBuffer.readRawBytes(8);
            body.fromTime = KerberosTime::fromBytes(timeBytes);
        }
        
        // tillTime
        std::vector<uint8_t> tillTimeBytes = newBuffer.readRawBytes(8);
        body.tillTime = KerberosTime::fromBytes(tillTimeBytes);
        
        // rtime (optional)
        int32_t hasRtime = newBuffer.readInt32();
        if (hasRtime) {
            std::vector<uint8_t> rtimeBytes = newBuffer.readRawBytes(8);
            body.rtime = KerberosTime::fromBytes(rtimeBytes);
        }
        
        // nonce
        body.nonce = newBuffer.readInt32();
        
        // etypes
        int32_t etypeCount = newBuffer.readInt32();
        for (int i = 0; i < etypeCount; i++) {
            body.etypes.push_back(newBuffer.readInt32());
        }
        
        // Skip addresses, authorization_data, and additional_tickets parsing
        
        return {body, newBuffer};
    }
};

class AsReq {
public:
    int32_t pvno = 5;  // Protocol version number
    int32_t msgType = static_cast<int32_t>(KrbMessageType::AS_REQ);
    std::optional<std::vector<PaData>> padata;
    KdcReqBody reqBody;
    
    AsReq() = default;
    
    std::vector<uint8_t> toBytes() const {
        ByteBuffer buffer;
        buffer.writeInt32(pvno);
        buffer.writeInt32(msgType);
        
        // padata (optional)
        if (padata.has_value()) {
            buffer.writeInt32(1);  // Has padata
            buffer.writeInt32(static_cast<int32_t>(padata->size()));
            for (const auto& pa : *padata) {
                buffer.writeRawBytes(pa.toBytes());
            }
        } else {
            buffer.writeInt32(0);  // No padata
        }
        
        // reqBody
        buffer.writeRawBytes(reqBody.toBytes());
        
        return buffer.getBuffer();
    }
    
    static AsReq fromBytes(const std::vector<uint8_t>& data) {
        ByteBuffer buffer(data);
        AsReq asReq;
        
        asReq.pvno = buffer.readInt32();
        asReq.msgType = buffer.readInt32();
        
        if (asReq.msgType != static_cast<int32_t>(KrbMessageType::AS_REQ)) {
            throw std::runtime_error("Expected AS_REQ (10), got " + std::to_string(asReq.msgType));
        }
        
        // padata (optional)
        int32_t hasPadata = buffer.readInt32();
        if (hasPadata) {
            int32_t padataCount = buffer.readInt32();
            std::vector<PaData> padata;
            
            for (int i = 0; i < padataCount; i++) {
                auto [pa, newBuffer] = PaData::fromBytes(buffer);
                padata.push_back(pa);
                buffer = newBuffer;
            }
            
            asReq.padata = padata;
        }
        
        // reqBody
        auto [reqBody, _] = KdcReqBody::fromBytes(buffer);
        asReq.reqBody = reqBody;
        
        return asReq;
    }
};

class Ticket {
public:
    int32_t tktVno = 5;
    std::string realm;
    PrincipalName sname;
    EncryptedData encPart;
    
    Ticket() = default;
    
    Ticket(const std::string& realm, const PrincipalName& sname, const EncryptedData& encPart)
        : realm(realm), sname(sname), encPart(encPart) {}
    
    std::vector<uint8_t> toBytes() const {
        ByteBuffer buffer;
        buffer.writeInt32(tktVno);
        buffer.writeString(realm);
        buffer.writeRawBytes(sname.toBytes());
        buffer.writeRawBytes(encPart.toBytes());
        
        return buffer.getBuffer();
    }
    
    static std::pair<Ticket, ByteBuffer> fromBytes(const ByteBuffer& buffer) {
        ByteBuffer newBuffer = buffer;
        
        int32_t tktVno = newBuffer.readInt32();
        std::string realm = newBuffer.readString();
        
        auto [sname, buffer1] = PrincipalName::fromBytes(newBuffer);
        newBuffer = buffer1;
        
        auto [encPart, buffer2] = EncryptedData::fromBytes(newBuffer);
        
        Ticket ticket;
        ticket.tktVno = tktVno;
        ticket.realm = realm;
        ticket.sname = sname;
        ticket.encPart = encPart;
        
        return {ticket, buffer2};
    }
};

class AsRep {
public:
    int32_t pvno = 5;
    int32_t msgType = static_cast<int32_t>(KrbMessageType::AS_REP);
    std::optional<std::vector<PaData>> padata;
    std::string crealm;
    PrincipalName cname;
    Ticket ticket;
    EncryptedData encPart;
    
    AsRep() = default;
    
    std::vector<uint8_t> toBytes() const {
        ByteBuffer buffer;
        buffer.writeInt32(pvno);
        buffer.writeInt32(msgType);
        
        // padata (optional)
        if (padata.has_value()) {
            buffer.writeInt32(1);  // Has padata
            buffer.writeInt32(static_cast<int32_t>(padata->size()));
            for (const auto& pa : *padata) {
                buffer.writeRawBytes(pa.toBytes());
            }
        } else {
            buffer.writeInt32(0);  // No padata
        }
        
        // crealm
        buffer.writeString(crealm);
        
        // cname
        buffer.writeRawBytes(cname.toBytes());
        
        // ticket
        buffer.writeRawBytes(ticket.toBytes());
        
        // encPart
        buffer.writeRawBytes(encPart.toBytes());
        
        return buffer.getBuffer();
    }
};

class EncryptionKey {
public:
    int32_t keytype;
    std::vector<uint8_t> keyvalue;
    
    EncryptionKey() = default;
    
    EncryptionKey(int32_t keytype, const std::vector<uint8_t>& keyvalue)
        : keytype(keytype), keyvalue(keyvalue) {}
    
    std::vector<uint8_t> toBytes() const {
        ByteBuffer buffer;
        buffer
    }}
// EncAsRepPart class to be encrypted in the AS_REP
class EncAsRepPart {
public:
    int32_t keyType;
    std::vector<uint8_t> keyValue;
    KerberosTime authTime;
    std::optional<KerberosTime> startTime;
    KerberosTime endTime;
    std::optional<KerberosTime> renewTill;
    int32_t nonce;
    
    EncAsRepPart() = default;
    
    std::vector<uint8_t> toBytes() const {
        ByteBuffer buffer;
        
        // key (EncryptionKey)
        buffer.writeInt32(keyType);
        buffer.writeBytes(keyValue);
        
        // times
        buffer.writeRawBytes(authTime.toBytes());
        
        // startTime (optional)
        if (startTime.has_value()) {
            buffer.writeInt32(1);  // Has startTime
            buffer.writeRawBytes(startTime->toBytes());
        } else {
            buffer.writeInt32(0);  // No startTime
        }
        
        buffer.writeRawBytes(endTime.toBytes());
        
        // renewTill (optional)
        if (renewTill.has_value()) {
            buffer.writeInt32(1);  // Has renewTill
            buffer.writeRawBytes(renewTill->toBytes());
        } else {
            buffer.writeInt32(0);  // No renewTill
        }
        
        // nonce
        buffer.writeInt32(nonce);
        
        return buffer.getBuffer();
    }
};

// EncTicketPart class to be encrypted in the Ticket
class EncTicketPart {
public:
    int32_t flags = 0;
    int32_t keyType;
    std::vector<uint8_t> keyValue;
    std::string crealm;
    PrincipalName cname;
    KerberosTime authTime;
    std::optional<KerberosTime> startTime;
    KerberosTime endTime;
    std::optional<KerberosTime> renewTill;
    
    EncTicketPart() = default;
    
    std::vector<uint8_t> toBytes() const {
        ByteBuffer buffer;
        
        // flags
        buffer.writeInt32(flags);
        
        // key (EncryptionKey)
        buffer.writeInt32(keyType);
        buffer.writeBytes(keyValue);
        
        // crealm
        buffer.writeString(crealm);
        
        // cname
        buffer.writeRawBytes(cname.toBytes());
        
        // times
        buffer.writeRawBytes(authTime.toBytes());
        
        // startTime (optional)
        if (startTime.has_value()) {
            buffer.writeInt32(1);  // Has startTime
            buffer.writeRawBytes(startTime->toBytes());
        } else {
            buffer.writeInt32(0);  // No startTime
        }
        
        buffer.writeRawBytes(endTime.toBytes());
        
        // renewTill (optional)
        if (renewTill.has_value()) {
            buffer.writeInt32(1);  // Has renewTill
            buffer.writeRawBytes(renewTill->toBytes());
        } else {
            buffer.writeInt32(0);  // No renewTill
        }
        
        return buffer.getBuffer();
    }
};

// User Database for Authentication Server
class KerberosUserDatabase {
private:
    struct UserEntry {
        std::string password;
        std::map<EncryptionType, std::vector<uint8_t>> keys;
    };
    
    std::map<std::string, UserEntry> users;
    std::string realm;

public:
    explicit KerberosUserDatabase(const std::string& realm) : realm(realm) {}
    
    void addUser(const std::string& username, const std::string& password) {
        UserEntry entry;
        entry.password = password;
        
        // Pre-compute keys for different encryption types
        std::string salt = realm + username;
        
        entry.keys[EncryptionType::AES256_CTS_HMAC_SHA1] = 
            KerberosCrypto::stringToKey(password, salt, EncryptionType::AES256_CTS_HMAC_SHA1);
        
        entry.keys[EncryptionType::AES128_CTS_HMAC_SHA1] = 
            KerberosCrypto::stringToKey(password, salt, EncryptionType::AES128_CTS_HMAC_SHA1);
        
        entry.keys[EncryptionType::RC4_HMAC] = 
            KerberosCrypto::stringToKey(password, salt, EncryptionType::RC4_HMAC);
        
        users[username] = entry;
    }
    
    bool validateUser(const std::string& username) const {
        return users.find(username) != users.end();
    }
    
    std::optional<std::vector<uint8_t>> getUserKey(const std::string& username, EncryptionType encryptionType) const {
        auto userIt = users.find(username);
        if (userIt == users.end()) {
            return std::nullopt;
        }
        
        auto keyIt = userIt->second.keys.find(encryptionType);
        if (keyIt == userIt->second.keys.end()) {
            return std::nullopt;
        }
        
        return keyIt->second;
    }
    
    std::string getRealm() const {
        return realm;
    }
};

// Service Database for Authentication Server
class KerberosServiceDatabase {
private:
    struct ServiceEntry {
        std::map<EncryptionType, std::vector<uint8_t>> keys;
        int32_t kvno;
    };
    
    std::map<std::string, ServiceEntry> services;
    std::string realm;

public:
    explicit KerberosServiceDatabase(const std::string& realm) : realm(realm) {}
    
    void addService(const std::string& serviceName, const std::vector<uint8_t>& key, EncryptionType encryptionType, int32_t kvno = 1) {
        auto it = services.find(serviceName);
        if (it == services.end()) {
            services[serviceName] = ServiceEntry{{}, kvno};
        }
        
        services[serviceName].keys[encryptionType] = key;
    }
    
    std::optional<std::vector<uint8_t>> getServiceKey(const std::string& serviceName, EncryptionType encryptionType) const {
        auto serviceIt = services.find(serviceName);
        if (serviceIt == services.end()) {
            return std::nullopt;
        }
        
        auto keyIt = serviceIt->second.keys.find(encryptionType);
        if (keyIt == serviceIt->second.keys.end()) {
            return std::nullopt;
        }
        
        return keyIt->second;
    }
    
    std::optional<int32_t> getServiceKvno(const std::string& serviceName) const {
        auto serviceIt = services.find(serviceName);
        if (serviceIt == services.end()) {
            return std::nullopt;
        }
        
        return serviceIt->second.kvno;
    }
    
    std::string getRealm() const {
        return realm;
    }
};

// Authentication Server (AS) that handles AS_REQ messages
class AuthenticationServer {
private:
    KerberosUserDatabase userDatabase;
    KerberosServiceDatabase serviceDatabase;
    std::string tgsServiceName;
    
    // Process pre-authentication data
    bool validatePreAuthentication(const AsReq& asReq, const std::string& username) {
        if (!asReq.padata.has_value()) {
            return false; // Pre-authentication required
        }
        
        for (const auto& pa : *asReq.padata) {
            if (pa.padataType == static_cast<int32_t>(PaDataType::ENC_TIMESTAMP)) {
                // Find supported encryption type
                EncryptionType encType = EncryptionType::RC4_HMAC; // Default
                
                for (int32_t etype : asReq.reqBody.etypes) {
                    if (userDatabase.getUserKey(username, static_cast<EncryptionType>(etype)).has_value()) {
                        encType = static_cast<EncryptionType>(etype);
                        break;
                    }
                }
                
                auto userKey = userDatabase.getUserKey(username, encType);
                if (!userKey.has_value()) {
                    return false;
                }
                
                try {
                    // Decrypt the encrypted timestamp
                    std::vector<uint8_t> decrypted = KerberosCrypto::decrypt(pa.padataValue, *userKey, encType);
                    
                    // Parse the timestamp (simplified validation)
                    KerberosTime timestamp = KerberosTime::fromBytes(decrypted);
                    
                    // Check if timestamp is within reasonable range (e.g., 5 minutes)
                    auto now = std::chrono::system_clock::now();
                    auto diff = std::chrono::duration_cast<std::chrono::minutes>(
                        now - timestamp.getTimestamp()).count();
                    
                    return std::abs(diff) <= 5; // Within 5 minutes
                } catch (const std::exception& e) {
                    return false;
                }
            }
        }
        
        return false; // No valid pre-auth found
    }
    
    // Generate a random session key
    std::pair<int32_t, std::vector<uint8_t>> generateSessionKey(EncryptionType preferredType) {
        // Generate a random key for the session
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> distrib(0, 255);
        
        size_t keySize = 16; // Default for AES128
        
        if (preferredType == EncryptionType::AES256_CTS_HMAC_SHA1) {
            keySize = 32;
        } else if (preferredType == EncryptionType::RC4_HMAC) {
            keySize = 16;
        }
        
        std::vector<uint8_t> key(keySize);
        for (size_t i = 0; i < keySize; i++) {
            key[i] = static_cast<uint8_t>(distrib(gen));
        }
        
        return {static_cast<int32_t>(preferredType), key};
    }
    
    // Generate nonce for messages
    int32_t generateNonce() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int32_t> distrib;
        return distrib(gen);
    }

public:
    AuthenticationServer(const std::string& realm, const std::string& tgsServiceName)
        : userDatabase(realm), serviceDatabase(realm), tgsServiceName(tgsServiceName) {}
    
    // Add a user to the database
    void addUser(const std::string& username, const std::string& password) {
        userDatabase.addUser(username, password);
    }
    
    // Add a service to the database
    void addService(const std::string& serviceName, const std::string& password) {
        // For simplicity, we'll use the same key derivation as for users
        std::string salt = userDatabase.getRealm() + serviceName;
        
        std::vector<uint8_t> aes256Key = KerberosCrypto::stringToKey(
            password, salt, EncryptionType::AES256_CTS_HMAC_SHA1);
        
        std::vector<uint8_t> aes128Key = KerberosCrypto::stringToKey(
            password, salt, EncryptionType::AES128_CTS_HMAC_SHA1);
        
        std::vector<uint8_t> rc4Key = KerberosCrypto::stringToKey(
            password, salt, EncryptionType::RC4_HMAC);
        
        serviceDatabase.addService(serviceName, aes256Key, EncryptionType::AES256_CTS_HMAC_SHA1);
        serviceDatabase.addService(serviceName, aes128Key, EncryptionType::AES128_CTS_HMAC_SHA1);
        serviceDatabase.addService(serviceName, rc4Key, EncryptionType::RC4_HMAC);
    }
    
    // Process an AS_REQ message and generate an AS_REP response
    std::optional<std::vector<uint8_t>> processAsReq(const std::vector<uint8_t>& asReqBytes) {
        try {
            // Parse the AS_REQ message
            AsReq asReq = AsReq::fromBytes(asReqBytes);
            
            // Validate the message structure
            if (asReq.pvno != 5 || asReq.msgType != static_cast<int32_t>(KrbMessageType::AS_REQ)) {
                return std::nullopt;
            }
            
            // Check if client principal name is provided
            if (!asReq.reqBody.cname.has_value()) {
                return std::nullopt;
            }
            
            // Get the username from the principal name
            std::string username = asReq.reqBody.cname->toString();
            
            // Validate the user exists in our database
            if (!userDatabase.validateUser(username)) {
                return std::nullopt;
            }
            
            // Validate pre-authentication data if provided
            if (!validatePreAuthentication(asReq, username)) {
                // Generate error response for pre-authentication required
                // In a real implementation, this would be a KRB_ERROR message
                return std::nullopt;
            }
            
            // Find the best supported encryption type
            std::optional<EncryptionType> selectedEtype;
            for (int32_t etype : asReq.reqBody.etypes) {
                EncryptionType encType = static_cast<EncryptionType>(etype);
                if (userDatabase.getUserKey(username, encType).has_value()) {
                    selectedEtype = encType;
                    break;
                }
            }
            
            if (!selectedEtype.has_value()) {
                return std::nullopt; // No supported encryption type
            }
            
            // Check if the server principal is the TGS
            std::string serverPrincipal;
            if (asReq.reqBody.sname.has_value()) {
                serverPrincipal = asReq.reqBody.sname->toString();
            } else {
                serverPrincipal = tgsServiceName;
            }
            
            // Generate a session key for the client
            auto [keyType, sessionKey] = generateSessionKey(*selectedEtype);
            
            // Create the ticket for the TGS
            EncTicketPart ticketPart;
            ticketPart.flags = asReq.reqBody.kdcOptions.flags;
            ticketPart.keyType = keyType;
            ticketPart.keyValue = sessionKey;
            ticketPart.crealm = userDatabase.getRealm();
            ticketPart.cname = *asReq.reqBody.cname;
            ticketPart.authTime = KerberosTime::now();
            ticketPart.endTime = asReq.reqBody.tillTime;
            
            if (asReq.reqBody.fromTime.has_value()) {
                ticketPart.startTime = *asReq.reqBody.fromTime;
            }
            
            if (asReq.reqBody.rtime.has_value() && asReq.reqBody.kdcOptions.isSet(KdcOptions::RENEWABLE)) {
                ticketPart.renewTill = *asReq.reqBody.rtime;
            }
            
            // Get the TGS service key
            auto tgsKey = serviceDatabase.getServiceKey(tgsServiceName, *selectedEtype);
            if (!tgsKey.has_value()) {
                return std::nullopt;
            }
            
            // Encrypt the ticket part with the TGS key
            std::vector<uint8_t> encTicketData = KerberosCrypto::encrypt(
                ticketPart.toBytes(), *tgsKey, *selectedEtype);
            
            // Create the encrypted part for the client
            EncAsRepPart encRepPart;
            encRepPart.keyType = keyType;
            encRepPart.keyValue = sessionKey;
            encRepPart.authTime = ticketPart.authTime;
            encRepPart.startTime = ticketPart.startTime;
            encRepPart.endTime = ticketPart.endTime;
            encRepPart.renewTill = ticketPart.renewTill;
            encRepPart.nonce = asReq.reqBody.nonce;
            
            // Get client key
            auto clientKey = userDatabase.getUserKey(username, *selectedEtype);
            if (!clientKey.has_value()) {
                return std::nullopt;
            }
            
            // Encrypt the AS_REP part with the client's key
            std::vector<uint8_t> encClientData = KerberosCrypto::encrypt(
                encRepPart.toBytes(), *clientKey, *selectedEtype);
            
            // Build the AS_REP message
            AsRep asRep;
            asRep.pvno = 5;
            asRep.msgType = static_cast<int32_t>(KrbMessageType::AS_REP);
            asRep.crealm = userDatabase.getRealm();
            asRep.cname = *asReq.reqBody.cname;
            
            // Create the Ticket
            Ticket tgt;
            tgt.realm = userDatabase.getRealm();
            
            // Create server principal name for the ticket
            PrincipalName serverName;
            serverName.nameType = static_cast<int32_t>(PrincipalNameType::SRV_INST);
            serverName.nameString = {tgsServiceName, userDatabase.getRealm()};
            tgt.sname = serverName;
            
            // Set encrypted part of the ticket
            tgt.encPart.etype = static_cast<int32_t>(*selectedEtype);
            tgt.encPart.kvno = serviceDatabase.getServiceKvno(tgsServiceName);
            tgt.encPart.cipher = encTicketData;
            
            asRep.ticket = tgt;
            
            // Set encrypted data for client
            asRep.encPart.etype = static_cast<int32_t>(*selectedEtype);
            asRep.encPart.kvno = std::nullopt;  // Client key version not needed
            asRep.encPart.cipher = encClientData;
            
            // Serialize the AS_REP message
            return asRep.toBytes();
            
        } catch (const std::exception& e) {
            std::cerr << "Error processing AS_REQ: " << e.what() << std::endl;
            return std::nullopt;
        }
    }
};

// Simple example server that listens for AS_REQ messages
void runKerberosServer() {
    // Initialize the Authentication Server
    AuthenticationServer as("EXAMPLE.COM", "krbtgt");
    
    // Add some test users
    as.addUser("testuser", "password123");
    as.addUser("admin", "adminpass");
    
    // Add the TGS service
    as.addService("krbtgt", "tgsSecretKey");
    
    // Add some application services
    as.addService("host", "hostSecret");
    as.addService("http", "webSecret");
    
    std::cout << "Kerberos AS Server started. Waiting for requests..." << std::endl;
    
    // In a real implementation, this would be a TCP or UDP server listening on port 88
    // For simplicity, we'll just simulate receiving a request
    
    // Example of how to process an AS_REQ message
    std::cout << "Simulating an AS_REQ message..." << std::endl;
    
    // Create a sample AS_REQ message
    AsReq asReq;
    asReq.pvno = 5;
    asReq.msgType = static_cast<int32_t>(KrbMessageType::AS_REQ);
    
    KdcReqBody reqBody;
    reqBody.kdcOptions.flags = KdcOptions::FORWARDABLE | KdcOptions::RENEWABLE;
    
    PrincipalName cname;
    cname.nameType = static_cast<int32_t>(PrincipalNameType::PRINCIPAL);
    cname.nameString = {"testuser"};
    reqBody.cname = cname;
    
    reqBody.realm = "EXAMPLE.COM";
    
    PrincipalName sname;
    sname.nameType = static_cast<int32_t>(PrincipalNameType::SRV_INST);
    sname.nameString = {"krbtgt", "EXAMPLE.COM"};
    reqBody.sname = sname;
    
    reqBody.tillTime = KerberosTime(time(nullptr) + 36000);  // Valid for 10 hours
    reqBody.nonce = 12345;
    reqBody.etypes = {
        static_cast<int32_t>(EncryptionType::AES256_CTS_HMAC_SHA1),
        static_cast<int32_t>(EncryptionType::AES128_CTS_HMAC_SHA1),
        static_cast<int32_t>(EncryptionType::RC4_HMAC)
    };
    
    asReq.reqBody = reqBody;
    
    // Simulate pre-authentication
    std::string username = "testuser";
    std::string password = "password123";
    std::string salt = "EXAMPLE.COM" + username;
    
    std::vector<uint8_t> key = KerberosCrypto::stringToKey(
        password, salt, EncryptionType::AES256_CTS_HMAC_SHA1);
    
    KerberosTime timestamp = KerberosTime::now();
    std::vector<uint8_t> encTimestamp = KerberosCrypto::encrypt(
        timestamp.toBytes(), key, EncryptionType::AES256_CTS_HMAC_SHA1);
    
    PaData padata;
    padata.padataType = static_cast<int32_t>(PaDataType::ENC_TIMESTAMP);
    padata.padataValue = encTimestamp;
    
    asReq.padata = std::vector<PaData>{padata};
    
    // Serialize the AS_REQ
    std::vector<uint8_t> asReqBytes = asReq.toBytes();
    
    // Process the request
    auto asRepBytes = as.processAsReq(asReqBytes);
    
    if (asRepBytes.has_value()) {
        std::cout << "AS_REQ processed successfully. Generated AS_REP response of " 
                 << asRepBytes->size() << " bytes." << std::endl;
    } else {
        std::cout << "Failed to process AS_REQ message." << std::endl;
    }
}

// Main function to demonstrate AS Server
int main() {
    std::cout << "Starting Kerberos Authentication Server demo..." << std::endl;
    
    // Initialize OpenSSL
    #if OPENSSL_VERSION_NUMBER < 0x10100000L
    OpenSSL_add_all_algorithms();
    #endif
    
    runKerberosServer();
    
    // Cleanup OpenSSL
    #if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_cleanup();
    #endif
    
    return 0;
}