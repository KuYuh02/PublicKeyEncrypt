#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <algorithm>
#include <ctime>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// Part 1: Password Guessing
class PasswordGuesser {
private:
    std::vector<std::string> commonPasswords;
    std::vector<std::string> patterns;
    std::vector<std::string> classmates;
    std::mt19937 rng;
    
    // Character set: lowercase + digits + -=.,/
    const std::string charset = "abcdefghijklmnopqrstuvwxyz0123456789-=.,/";
    
    // Generate a random 6-character password
    std::string generateRandomPassword() {
        std::string password;
        std::uniform_int_distribution<int> dist(0, charset.size() - 1);
        
        for (int i = 0; i < 6; i++) {
            password += charset[dist(rng)];
        }
        
        return password;
    }
    
    // Generate a password based on patterns
    std::string generatePatternPassword() {
        if (patterns.empty()) return generateRandomPassword();
        
        std::uniform_int_distribution<int> dist(0, patterns.size() - 1);
        return patterns[dist(rng)];
    }
    
public:
    PasswordGuesser() {
        // Seed the random number generator
        rng.seed(std::time(nullptr));
        
        // Initialize with some common password patterns (these are examples)
        initializeCommonPasswords();
        initializePatterns();
        initializeClassmates();
    }
    
    void initializeCommonPasswords() {
        // Add some common 6-character passwords
        commonPasswords = {
            "123456", "qwerty", "abc123", "letmein", "monkey", "111111",
            "dragon", "shadow", "master", "666666", "qwerty1", "123123",
            "888888", "654321", "1q2w3e", "121212", "qazwsx", "abcdef",
            "trustno1", "hello1", "monkey1", "1234qw", "test123", "soccer",
            "killer", "princess", "admin1", "welcome", "admin.", "password1"
        };
    }
    
    void initializePatterns() {
        // Initialize patterns that might be common in passwords
        patterns = {
            // Month + year combinations
            "jan2024", "feb2024", "mar2024", "apr2024", "may2024", "jun2024",
            "jul2024", "aug2024", "sep2024", "oct2024", "nov2024", "dec2024",
            
            // Common word + digit patterns
            "pass12", "admin1", "login1", "user12", "test12", "demo12", 
            
            // Sequential characters
            "abcdef", "123456", "qwerty",
            
            // Repeated patterns
            "aaaaaa", "111111", "222222", "333333", "444444", "555555",
            
            // Keyboard patterns
            "qweasd", "asdfgh", "zxcvbn", "1qaz2w", "2wsx3e", "3edc4r",
            
            // Year combinations
            "202400", "202401", "202402", "202403", "202404", "202405"
        };
        
        // Add variations with special characters
        std::vector<std::string> variations;
        for (const auto& pattern : patterns) {
            // Replace some characters with special chars
            std::string var1 = pattern;
            if (var1.find('o') != std::string::npos) var1.replace(var1.find('o'), 1, "0");
            variations.push_back(var1);
            
            std::string var2 = pattern;
            if (var2.find('i') != std::string::npos) var2.replace(var2.find('i'), 1, "1");
            variations.push_back(var2);
            
            std::string var3 = pattern;
            if (var3.find('e') != std::string::npos) var3.replace(var3.find('e'), 1, "3");
            variations.push_back(var3);
            
            std::string var4 = pattern;
            if (var4.find('a') != std::string::npos) var4.replace(var4.find('a'), 1, "@");
            variations.push_back(var4);
        }
        
        // Combine original patterns with variations
        patterns.insert(patterns.end(), variations.begin(), variations.end());
    }
    
    void initializeClassmates() {
        // This would be filled with classmates' names, usernames, etc.
        // For now, we'll use placeholders - replace with actual names if available
        classmates = {
            "user01", "user02", "user03", "user04", "user05",
            "user06", "user07", "user08", "user09", "user10"
        };
        
        // Add variations of classmate names (transform to likely passwords)
        std::vector<std::string> variations;
        for (const auto& name : classmates) {
            // Add variations with digits
            variations.push_back(name + "1");
            variations.push_back(name + "12");
            variations.push_back(name + "123");
            
            // Add variations with special chars
            std::string var = name;
            var.replace(0, 1, 1, std::toupper(var[0]));
            variations.push_back(var);
            
            // More sophisticated variations could be added here
        }
        
        // Add all variations to our guesses
        classmates.insert(classmates.end(), variations.begin(), variations.end());
        
        // Filter to only keep 6-character passwords
        classmates.erase(
            std::remove_if(classmates.begin(), classmates.end(), 
                [](const std::string& s) { return s.length() != 6; }),
            classmates.end());
    }
    
    std::string guessPassword(int attempt) {
        // Strategy: 
        // - First 30 attempts: try common passwords
        // - Next 100 attempts: try classmate-based passwords
        // - Next 200 attempts: try pattern-based passwords
        // - Remaining attempts: try random combinations with some patterns mixed in
        
        if (attempt < commonPasswords.size()) {
            return commonPasswords[attempt];
        } 
        else if (attempt < commonPasswords.size() + classmates.size()) {
            return classmates[attempt - commonPasswords.size()];
        }
        else if (attempt % 10 == 0) {
            // Every 10th attempt, try a pattern-based password
            return generatePatternPassword();
        }
        else {
            // Otherwise, try a completely random password
            return generateRandomPassword();
        }
    }
};

// Part 2: Public Key Cryptography using OpenSSL
class Cryptography {
private:
    RSA *myPrivateKey;
    RSA *theirPublicKey;
    
    // Error handling
    void handleErrors() {
        ERR_print_errors_fp(stderr);
        abort();
    }
    
public:
    Cryptography() : myPrivateKey(nullptr), theirPublicKey(nullptr) {
        // Initialize OpenSSL
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    }
    
    ~Cryptography() {
        // Clean up
        if (myPrivateKey) RSA_free(myPrivateKey);
        if (theirPublicKey) RSA_free(theirPublicKey);
        EVP_cleanup();
        ERR_free_strings();
    }
    
    // Load my private key from file
    void loadMyPrivateKey(const std::string& filename) {
        FILE* fp = fopen(filename.c_str(), "r");
        if (!fp) {
            std::cerr << "Failed to open private key file" << std::endl;
            return;
        }
        
        myPrivateKey = PEM_read_RSAPrivateKey(fp, nullptr, nullptr, nullptr);
        fclose(fp);
        
        if (!myPrivateKey) {
            handleErrors();
        }
    }
    
    // Load their public key from file
    void loadTheirPublicKey(const std::string& filename) {
        FILE* fp = fopen(filename.c_str(), "r");
        if (!fp) {
            std::cerr << "Failed to open public key file" << std::endl;
            return;
        }
        
        theirPublicKey = PEM_read_RSA_PUBKEY(fp, nullptr, nullptr, nullptr);
        fclose(fp);
        
        if (!theirPublicKey) {
            handleErrors();
        }
    }
    
    // Decrypt a message using my private key
    std::string decrypt(const std::string& ciphertext) {
        if (!myPrivateKey) {
            std::cerr << "Private key not loaded" << std::endl;
            return "";
        }
        
        // Convert hex string to binary
        std::vector<unsigned char> binary;
        for (size_t i = 0; i < ciphertext.length(); i += 2) {
            std::string byteString = ciphertext.substr(i, 2);
            unsigned char byte = (unsigned char) std::stoi(byteString, nullptr, 16);
            binary.push_back(byte);
        }
        
        // Prepare output buffer
        std::vector<unsigned char> decrypted(RSA_size(myPrivateKey));
        
        // Decrypt
        int result = RSA_private_decrypt(
            binary.size(),
            binary.data(),
            decrypted.data(),
            myPrivateKey,
            RSA_PKCS1_PADDING
        );
        
        if (result == -1) {
            handleErrors();
            return "";
        }
        
        // Convert to string and return
        return std::string(decrypted.begin(), decrypted.begin() + result);
    }
    
    // Encrypt a message using their public key
    std::string encrypt(const std::string& plaintext) {
        if (!theirPublicKey) {
            std::cerr << "Public key not loaded" << std::endl;
            return "";
        }
        
        // Prepare output buffer
        std::vector<unsigned char> encrypted(RSA_size(theirPublicKey));
        
        // Encrypt
        int result = RSA_public_encrypt(
            plaintext.length(),
            reinterpret_cast<const unsigned char*>(plaintext.c_str()),
            encrypted.data(),
            theirPublicKey,
            RSA_PKCS1_PADDING
        );
        
        if (result == -1) {
            handleErrors();
            return "";
        }
        
        // Convert to hex string
        std::string hexOutput;
        for (int i = 0; i < result; ++i) {
            char hex[3];
            sprintf(hex, "%02x", encrypted[i]);
            hexOutput += hex;
        }
        
        return hexOutput;
    }
};

// Function prototype for the external guess function
// This will be provided by the assignment framework
extern bool guess(const std::string& password);

// Main function that ties everything together
int main(int argc, char* argv[]) {
    // Part 1: Password Guessing
    PasswordGuesser passwordGuesser;
    int points = 0;
    
    // Make 1,000,000 guesses
    for (int i = 0; i < 1000000; ++i) {
        std::string passwordAttempt = passwordGuesser.guessPassword(i);
        
        // Call the external guess function
        if (guess(passwordAttempt)) {
            // Password found! Increment points
            points++;
            std::cout << "Password found: " << passwordAttempt << std::endl;
        }
    }
    
    std::cout << "Total points: " << points << std::endl;
    
    // Part 2: Public Key Cryptography
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <my_private_key.pem> <their_public_key.pem> <encrypted_message>" << std::endl;
        return 1;
    }
    
    Cryptography crypto;
    
    // Load keys
    crypto.loadMyPrivateKey(argv[1]);
    crypto.loadTheirPublicKey(argv[2]);
    
    // Decrypt the message from command line
    std::string encryptedMessage = argv[3];
    std::string decryptedMessage = crypto.decrypt(encryptedMessage);
    
    std::cout << "Decrypted message: " << decryptedMessage << std::endl;
    
    // Get message to encrypt from user
    std::string messageToEncrypt;
    std::cout << "Enter message to encrypt: ";
    std::getline(std::cin, messageToEncrypt);
    
    // Encrypt and display
    std::string encryptedResponse = crypto.encrypt(messageToEncrypt);
    std::cout << "Encrypted message: " << encryptedResponse << std::endl;
    
    return 0;
}
