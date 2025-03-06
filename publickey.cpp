#include <iostream>
#include <string>
#include <unordered_set>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// Placeholder for password guessing
std::unordered_set<std::string> known_passwords = {"abc123", "password", "qwerty", "letmein"};

int guess_counter = 0;

int guess(const std::string& password) {
    guess_counter++;
    if (known_passwords.find(password) != known_passwords.end()) {
        return 10; // Assuming every hit is a classmate's password for simplicity
    }
    return 0;
}

// RSA key generation
RSA* generate_keypair(int bits) {
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);

    if (!RSA_generate_key_ex(rsa, bits, e, nullptr)) {
        std::cerr << "Error generating key pair\n";
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    BN_free(e);
    return rsa;
}

// Encrypt with public key
std::vector<unsigned char> encrypt(RSA* rsa, const std::string& message) {
    std::vector<unsigned char> encrypted(RSA_size(rsa));
    int result = RSA_public_encrypt(message.size(), (unsigned char*)message.c_str(), encrypted.data(), rsa, RSA_PKCS1_OAEP_PADDING);

    if (result == -1) {
        std::cerr << "Encryption failed\n";
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    encrypted.resize(result);
    return encrypted;
}

// Decrypt with private key
std::string decrypt(RSA* rsa, const std::vector<unsigned char>& encrypted) {
    std::vector<unsigned char> decrypted(RSA_size(rsa));
    int result = RSA_private_decrypt(encrypted.size(), encrypted.data(), decrypted.data(), rsa, RSA_PKCS1_OAEP_PADDING);

    if (result == -1) {
        std::cerr << "Decryption failed\n";
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return std::string(decrypted.begin(), decrypted.begin() + result);
}
