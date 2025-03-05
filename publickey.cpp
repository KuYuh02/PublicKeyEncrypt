#include <iostream>
#include <fstream>
#include <vector>
#include <set>
#include <string>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace std;

// -------------------------- PART 1: PASSWORD GUESSING --------------------------

// Generate common password guesses (simplified for demo)
vector<string> generate_password_guesses() {
    vector<string> guesses;
    vector<string> common = {"password", "123456", "qwerty", "abc123", "letmein", "monkey"};
    vector<string> patterns = {"pass12", "admin1", "hello1", "welcome"};

    for (const auto& word : common) {
        if (word.size() <= 6) guesses.push_back(word);
    }
    for (const auto& pat : patterns) {
        guesses.push_back(pat);
    }

    return guesses;
}

// Simulated guess function (in a real case, this would interact with a database)
bool guess(const string& password, const set<string>& database) {
    return database.count(password) > 0;
}

// -------------------------- PART 2: RSA ENCRYPTION & DECRYPTION --------------------------

// Generate RSA Key Pair
RSA* generate_key() {
    int bits = 2048;
    RSA* rsa = RSA_generate_key(bits, RSA_F4, nullptr, nullptr);
    return rsa;
}

// Encrypt a message
string rsa_encrypt(RSA* publicKey, const string& message) {
    vector<unsigned char> encrypted(RSA_size(publicKey));
    int result = RSA_public_encrypt(message.size(), (unsigned char*)message.c_str(),
                                    encrypted.data(), publicKey, RSA_PKCS1_OAEP_PADDING);
    if (result == -1) {
        cerr << "Encryption error: " << ERR_error_string(ERR_get_error(), nullptr) << endl;
        return "";
    }
    return string(encrypted.begin(), encrypted.end());
}

// Decrypt a message
string rsa_decrypt(RSA* privateKey, const string& encrypted) {
    vector<unsigned char> decrypted(RSA_size(privateKey));
    int result = RSA_private_decrypt(encrypted.size(), (unsigned char*)encrypted.c_str(),
                                     decrypted.data(), privateKey, RSA_PKCS1_OAEP_PADDING);
    if (result == -1) {
        cerr << "Decryption error: " << ERR_error_string(ERR_get_error(), nullptr) << endl;
        return "";
    }
    return string(decrypted.begin(), decrypted.end());
}

int main() {
    // ---------------------- PASSWORD GUESSING ----------------------
    set<string> passwordDatabase = {"abc123", "password", "letmein", "monkey", "admin1"};
    vector<string> guesses = generate_password_guesses();
    int score = 0;

    for (const auto& pw : guesses) {
        if (guess(pw, passwordDatabase)) {
            score++;
            cout << "Guessed password: " << pw << endl;
        }
    }
    cout << "Total score: " << score << endl;

    // ---------------------- RSA ENCRYPTION/DECRYPTION ----------------------
    RSA* rsaKeyPair = generate_key();
    string message = "SecretMessage";

    // Encrypt and decrypt
    string encrypted = rsa_encrypt(rsaKeyPair, message);
    string decrypted = rsa_decrypt(rsaKeyPair, encrypted);

    cout << "Original: " << message << endl;
    cout << "Decrypted: " << decrypted << endl;

    RSA_free(rsaKeyPair);
    return 0;
}
