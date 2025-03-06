#include <iostream>
#include <string>
#include <unordered_set>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>

// Part 1: Password Guessing
class PasswordGuesser {
private:
    std::unordered_set<std::string> database; // Simulated database of passwords
    std::unordered_set<std::string> classmates; // Simulated classmates' passwords
    int guessCounter;

public:
    PasswordGuesser() : guessCounter(0) {
        // Initialize with some example passwords (simulated database)
        database.insert("pass1");
        database.insert("123456");
        database.insert("qwerty");
        database.insert("letmein");
        database.insert("admin12");

        // Simulated classmates' passwords
        classmates.insert("class1");
        classmates.insert("mate22");
        classmates.insert("friend");
    }

    int guess(const std::string& password) {
        guessCounter++;
        if (database.find(password) != database.end()) {
            if (classmates.find(password) != classmates.end()) {
                return 10; // Classmate's password
            }
            return 1; // Regular password in the database
        }
        return 0; // Password not found
    }
};

// Part 2: Public Key Cryptography
class PublicKeyCrypto {
private:
    RSA* privateKey; // Your private key
    RSA* publicKey;  // Your public key
    RSA* theirPublicKey; // Their public key

public:
    PublicKeyCrypto() : privateKey(nullptr), publicKey(nullptr), theirPublicKey(nullptr) {
        // Generate your own RSA key pair
        generateKeyPair();
    }

    ~PublicKeyCrypto() {
        if (privateKey) RSA_free(privateKey);
        if (publicKey) RSA_free(publicKey);
        if (theirPublicKey) RSA_free(theirPublicKey);
    }

    void generateKeyPair() {
        privateKey = RSA_new();
        BIGNUM* e = BN_new();
        BN_set_word(e, RSA_F4);
        RSA_generate_key_ex(privateKey, 2048, e, nullptr);
        BN_free(e);

        // Extract public key from private key
        publicKey = RSAPublicKey_dup(privateKey);
    }

    void setTheirPublicKey(RSA* key) {
        theirPublicKey = RSAPublicKey_dup(key);
    }

    std::string decryptMessage(const std::string& encrypted) {
        std::string decrypted(RSA_size(privateKey), '\0');
        int len = RSA_private_decrypt(encrypted.size(), 
                                     reinterpret_cast<const unsigned char*>(encrypted.data()),
                                     reinterpret_cast<unsigned char*>(&decrypted[0]),
                                     privateKey, RSA_PKCS1_OAEP_PADDING);
        if (len == -1) {
            throw std::runtime_error("Decryption failed");
        }
        decrypted.resize(len);
        return decrypted;
    }

    std::string encryptMessage(const std::string& message) {
        std::string encrypted(RSA_size(theirPublicKey), '\0');
        int len = RSA_public_encrypt(message.size(),
                                    reinterpret_cast<const unsigned char*>(message.data()),
                                    reinterpret_cast<unsigned char*>(&encrypted[0]),
                                    theirPublicKey, RSA_PKCS1_OAEP_PADDING);
        if (len == -1) {
            throw std::runtime_error("Encryption failed");
        }
        encrypted.resize(len);
        return encrypted;
    }

    bool verifyHash(const std::string& message, const std::string& hash) {
        // Simulate hash verification using their public key
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, message.data(), message.size());
        SHA256_Final(digest, &sha256);

        std::string computedHash(reinterpret_cast<char*>(digest), SHA256_DIGEST_LENGTH);
        return computedHash == hash;
    }
};
