#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <random>
#include <fstream>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

// External function declared but not implemented here
// This will be provided by the testing environment
extern int guess(const std::string& password);

class PasswordGuesser {
private:
    // Common password patterns and strategies
    std::vector<std::string> commonPatterns;
    
    // Words for dictionary attack
    std::vector<std::string> dictionary;
    
    // Character sets for different strategies
    const std::string lowerAlpha = "abcdefghijklmnopqrstuvwxyz";
    const std::string digits = "0123456789";
    const std::string specialChars = "-=.,/";
    const std::string allChars = lowerAlpha + digits + specialChars;
    
    // Track guessed passwords to avoid repetition
    std::unordered_map<std::string, bool> guessedPasswords;
    
    // Random number generator
    std::mt19937 rng;
    
    // Load common words from file if available
    void loadDictionary() {
        // Common short words that might appear in passwords
        dictionary = {
            "admin", "pass", "word", "login", "user", "test", "game", 
            "home", "web", "site", "demo", "data", "mail", "info",
            "work", "job", "tech", "code", "dev", "app", "biz", "pro",
            "ace", "air", "all", "art", "bad", "bat", "bed", "big", "box",
            "boy", "bug", "bus", "car", "cat", "day", "dog", "eat", "egg",
            "end", "eye", "fan", "fly", "fox", "fun", "gas", "gun", "hat",
            "hit", "hot", "ice", "job", "key", "kid", "lab", "law", "leg",
            "let", "lie", "lip", "log", "low", "man", "map", "max", "mix",
            "mom", "net", "new", "now", "nut", "oil", "old", "one", "out",
            "own", "pay", "pen", "pet", "pig", "pin", "pit", "pop", "pot",
            "put", "red", "row", "run", "sad", "sea", "see", "set", "sex",
            "she", "sky", "son", "sun", "tag", "tax", "tea", "ten", "the",
            "tie", "tip", "top", "try", "two", "use", "war", "way", "web",
            "who", "why", "win", "yes", "yet", "you", "zip", "zoo",
            "love", "life", "live", "rock", "star", "blue", "cool", "best",
            "gold", "cash", "nice", "free", "hack", "king", "dead", "dark",
            "baby", "fire", "list", "play", "hero", "solo", "wild"
        };
        
        // Add common years and sequences
        for (int i = 1990; i <= 2024; i++) {
            dictionary.push_back(std::to_string(i));
        }
        
        for (int i = 0; i <= 999; i++) {
            dictionary.push_back(std::to_string(i));
            if (i < 100) dictionary.push_back("0" + std::to_string(i));
            if (i < 10) dictionary.push_back("00" + std::to_string(i));
        }
    }
    
    // Load common password patterns
    void initializePatterns() {
        commonPatterns = {
            // Common patterns people use
            "123456", "654321", "111111", "222222", "333333", "444444", 
            "555555", "666666", "777777", "888888", "999999", "000000",
            "abcdef", "qwerty", "asdfgh", "zxcvbn", "qazwsx", "passwd",
            "abc123", "123abc", "test123", "admin1", "123321", "password"
        };
    }
    
    // Generate passwords by combining words with numbers or special chars
    std::string generateMixedPassword() {
        std::string result;
        std::uniform_int_distribution<int> dictDist(0, dictionary.size() - 1);
        std::uniform_int_distribution<int> digitDist(0, digits.size() - 1);
        std::uniform_int_distribution<int> specialDist(0, specialChars.size() - 1);
        std::uniform_int_distribution<int> boolDist(0, 1);
        
        // Select a word from dictionary
        std::string word = dictionary[dictDist(rng)];
        
        // If word is too long, truncate it
        if (word.length() > 5) {
            word = word.substr(0, 5);
        }
        
        result = word;
        
        // Add digits or special chars to complete 6 characters
        while (result.length() < 6) {
            if (boolDist(rng) == 0) {
                result += digits[digitDist(rng)];
            } else {
                result += specialChars[specialDist(rng)];
            }
        }
        
        return result;
    }
    
    // Generate a completely random password
    std::string generateRandomPassword() {
        std::string result;
        std::uniform_int_distribution<int> charDist(0, allChars.size() - 1);
        
        for (int i = 0; i < 6; i++) {
            result += allChars[charDist(rng)];
        }
        
        return result;
    }
    
    // Try password patterns common among students (based on course-related terms)
    std::string generateStudentPassword() {
        // Common patterns for students - these might be more likely for classmates
        std::vector<std::string> courseTerms = {
            "cs", "cpp", "java", "py", "code", "prog", "algo", "class", 
            "exam", "quiz", "test", "lab", "hw", "fall", "spring", "prof"
        };
        
        std::vector<std::string> years = {"22", "23", "24", "25"};
        std::vector<std::string> months = {"01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12"};
        
        std::uniform_int_distribution<int> termDist(0, courseTerms.size() - 1);
        std::uniform_int_distribution<int> yearDist(0, years.size() - 1);
        std::uniform_int_distribution<int> monthDist(0, months.size() - 1);
        std::uniform_int_distribution<int> digitDist(0, 9);
        
        std::string result;
        
        // Several strategies for student passwords
        int strategy = std::uniform_int_distribution<int>(0, 3)(rng);
        
        switch(strategy) {
            case 0: {
                // Course term + year + random digits
                std::string term = courseTerms[termDist(rng)];
                std::string year = years[yearDist(rng)];
                result = term + year;
                while (result.length() < 6) {
                    result += std::to_string(digitDist(rng));
                }
                if (result.length() > 6) {
                    result = result.substr(0, 6);
                }
                break;
            }
            case 1: {
                // First letters of course + month + year
                std::string term = courseTerms[termDist(rng)];
                term = term.length() > 2 ? term.substr(0, 2) : term;
                std::string month = months[monthDist(rng)];
                std::string year = years[yearDist(rng)];
                result = term + month + year;
                if (result.length() > 6) {
                    result = result.substr(0, 6);
                }
                break;
            }
            case 2: {
                // Simple pattern with course term
                std::string term = courseTerms[termDist(rng)];
                if (term.length() > 4) {
                    term = term.substr(0, 4);
                }
                result = term;
                while (result.length() < 6) {
                    result += std::to_string(digitDist(rng));
                }
                break;
            }
            case 3: {
                // School related patterns with special chars
                std::vector<std::string> patterns = {
                    "cs.101", "py-101", "cpp101", "code01", "java01", "cs/101", 
                    "py=101", "j.101", "c-101", "alg101", "dev101", "web101"
                };
                std::uniform_int_distribution<int> patternDist(0, patterns.size() - 1);
                result = patterns[patternDist(rng)];
                break;
            }
        }
        
        return result;
    }
    
public:
    PasswordGuesser() {
        // Initialize with time-based seed
        rng = std::mt19937(std::random_device{}());
        loadDictionary();
        initializePatterns();
    }
    
    // Main method to generate a million guesses
    void performGuesses(int numGuesses) {
        int numCommonPatterns = std::min(numGuesses / 10, static_cast<int>(commonPatterns.size()));
        int numStudentPatterns = numGuesses / 5;
        int numDictionaryBased = numGuesses / 2;
        int numRandom = numGuesses - numCommonPatterns - numStudentPatterns - numDictionaryBased;
        
        // 1. Try common patterns first
        for (int i = 0; i < numCommonPatterns; i++) {
            if (i < commonPatterns.size()) {
                std::string password = commonPatterns[i];
                if (guessedPasswords.find(password) == guessedPasswords.end()) {
                    guess(password);
                    guessedPasswords[password] = true;
                }
            }
        }
        
        // 2. Try student-specific patterns (focusing on classmates)
        for (int i = 0; i < numStudentPatterns; i++) {
            std::string password = generateStudentPassword();
            if (guessedPasswords.find(password) == guessedPasswords.end()) {
                guess(password);
                guessedPasswords[password] = true;
            }
        }
        
        // 3. Try dictionary-based passwords
        for (int i = 0; i < numDictionaryBased; i++) {
            std::string password = generateMixedPassword();
            if (guessedPasswords.find(password) == guessedPasswords.end()) {
                guess(password);
                guessedPasswords[password] = true;
            }
        }
        
        // 4. Fill remaining guesses with random passwords
        for (int i = 0; i < numRandom; i++) {
            std::string password = generateRandomPassword();
            if (guessedPasswords.find(password) == guessedPasswords.end()) {
                guess(password);
                guessedPasswords[password] = true;
            }
        }
    }
};

class CryptoHandler {
private:
    EVP_PKEY* myPrivateKey;
    EVP_PKEY* myPublicKey;
    EVP_PKEY* theirPublicKey;
    
    // Helper function to handle OpenSSL errors
    void handleErrors() {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    
    // Base64 encode
    std::string base64Encode(const unsigned char* buffer, size_t length) {
        BIO* bio = BIO_new(BIO_s_mem());
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO_push(b64, bio);
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO_write(b64, buffer, length);
        BIO_flush(b64);
        
        BUF_MEM* bufferPtr;
        BIO_get_mem_ptr(b64, &bufferPtr);
        std::string result(bufferPtr->data, bufferPtr->length);
        
        BIO_free_all(b64);
        return result;
    }
    
    // Base64 decode
    std::vector<unsigned char> base64Decode(const std::string& encoded) {
        BIO* bio = BIO_new_mem_buf(encoded.c_str(), -1);
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO_push(b64, bio);
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        
        std::vector<unsigned char> buffer(encoded.size());
        int decodedSize = BIO_read(b64, buffer.data(), encoded.size());
        buffer.resize(decodedSize);
        
        BIO_free_all(b64);
        return buffer;
    }

public:
    CryptoHandler() : myPrivateKey(nullptr), myPublicKey(nullptr), theirPublicKey(nullptr) {
        // Initialize OpenSSL
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    }
    
    ~CryptoHandler() {
        // Clean up
        if (myPrivateKey) EVP_PKEY_free(myPrivateKey);
        if (myPublicKey) EVP_PKEY_free(myPublicKey);
        if (theirPublicKey) EVP_PKEY_free(theirPublicKey);
        
        EVP_cleanup();
        ERR_free_strings();
    }
    
    // Load our private key from string
    void loadPrivateKey(const std::string& privateKeyPEM) {
        BIO* bio = BIO_new_mem_buf(privateKeyPEM.c_str(), -1);
        myPrivateKey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
        
        if (!myPrivateKey) {
            handleErrors();
        }
    }
    
    // Load our public key from string
    void loadMyPublicKey(const std::string& publicKeyPEM) {
        BIO* bio = BIO_new_mem_buf(publicKeyPEM.c_str(), -1);
        myPublicKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);
        
        if (!myPublicKey) {
            handleErrors();
        }
    }
    
    // Load their public key from string
    void loadTheirPublicKey(const std::string& publicKeyPEM) {
        BIO* bio = BIO_new_mem_buf(publicKeyPEM.c_str(), -1);
        theirPublicKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);
        
        if (!theirPublicKey) {
            handleErrors();
        }
    }
    
    // Decrypt a message using our private key
    std::string decryptMessage(const std::string& encryptedBase64) {
        if (!myPrivateKey) {
            std::cerr << "Private key not loaded" << std::endl;
            return "";
        }
        
        // Decode base64
        std::vector<unsigned char> encryptedData = base64Decode(encryptedBase64);
        
        // Get the maximum size for the decrypted data
        int keySize = EVP_PKEY_size(myPrivateKey);
        std::vector<unsigned char> decryptedData(keySize);
        
        // Create cipher context
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(myPrivateKey, NULL);
        if (!ctx) handleErrors();
        
        // Initialize decryption
        if (EVP_PKEY_decrypt_init(ctx) <= 0) handleErrors();
        
        // Set padding
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) handleErrors();
        
        // Decrypt
        size_t decryptedLength = decryptedData.size();
        if (EVP_PKEY_decrypt(ctx, decryptedData.data(), &decryptedLength, 
                            encryptedData.data(), encryptedData.size()) <= 0) {
            handleErrors();
        }
        
        // Cleanup
        EVP_PKEY_CTX_free(ctx);
        
        // Return as string
        return std::string(decryptedData.begin(), decryptedData.begin() + decryptedLength);
    }
    
    // Encrypt a message using their public key
    std::string encryptMessage(const std::string& message) {
        if (!theirPublicKey) {
            std::cerr << "Their public key not loaded" << std::endl;
            return "";
        }
        
        // Get the maximum size for the encrypted data
        int keySize = EVP_PKEY_size(theirPublicKey);
        std::vector<unsigned char> encryptedData(keySize);
        
        // Create cipher context
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(theirPublicKey, NULL);
        if (!ctx) handleErrors();
        
        // Initialize encryption
        if (EVP_PKEY_encrypt_init(ctx) <= 0) handleErrors();
        
        // Set padding
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) handleErrors();
        
        // Encrypt
        size_t encryptedLength = encryptedData.size();
        if (EVP_PKEY_encrypt(ctx, encryptedData.data(), &encryptedLength, 
                           reinterpret_cast<const unsigned char*>(message.c_str()), 
                           message.size()) <= 0) {
            handleErrors();
        }
        
        // Cleanup
        EVP_PKEY_CTX_free(ctx);
        
        // Return as base64
        return base64Encode(encryptedData.data(), encryptedLength);
    }
    
    // Verify a hash using their public key
    bool verifyHash(const std::string& message, const std::string& signatureBase64) {
        if (!theirPublicKey) {
            std::cerr << "Their public key not loaded" << std::endl;
            return false;
        }
        
        // Decode base64 signature
        std::vector<unsigned char> signature = base64Decode(signatureBase64);
        
        // Create verification context
        EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
        if (!mdctx) handleErrors();
        
        // Initialize verification
        if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, theirPublicKey) <= 0) {
            handleErrors();
        }
        
        // Update with message
        if (EVP_DigestVerifyUpdate(mdctx, message.c_str(), message.size()) <= 0) {
            handleErrors();
        }
        
        // Verify signature
        int result = EVP_DigestVerifyFinal(mdctx, signature.data(), signature.size());
        
        // Cleanup
        EVP_MD_CTX_destroy(mdctx);
        
        return result == 1;
    }
    
    // Create a hash using our private key
    std::string createHash(const std::string& message) {
        if (!myPrivateKey) {
            std::cerr << "Private key not loaded" << std::endl;
            return "";
        }
        
        // Create signing context
        EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
        if (!mdctx) handleErrors();
        
        // Initialize signing
        if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, myPrivateKey) <= 0) {
            handleErrors();
        }
        
        // Update with message
        if (EVP_DigestSignUpdate(mdctx, message.c_str(), message.size()) <= 0) {
            handleErrors();
        }
        
        // Get signature length
        size_t signatureLength;
        if (EVP_DigestSignFinal(mdctx, NULL, &signatureLength) <= 0) {
            handleErrors();
        }
        
        // Get signature
        std::vector<unsigned char> signature(signatureLength);
        if (EVP_DigestSignFinal(mdctx, signature.data(), &signatureLength) <= 0) {
            handleErrors();
        }
        
        // Cleanup
        EVP_MD_CTX_destroy(mdctx);
        
        // Return as base64
        return base64Encode(signature.data(), signatureLength);
    }
};

// The function that will be called to run the password guessing part
void runPasswordGuesser() {
    PasswordGuesser guesser;
    guesser.performGuesses(1000000); // Perform 1 million guesses
}

// Functions to handle the crypto part of the assignment
void loadKeysAndHandleCrypto(const std::string& myPublicKeyPEM, 
                           const std::string& myPrivateKeyPEM,
                           const std::string& theirPublicKeyPEM,
                           const std::string& encryptedMessage,
                           const std::string& messageToEncrypt) {
    
    CryptoHandler crypto;
    
    // Load keys
    crypto.loadPrivateKey(myPrivateKeyPEM);
    crypto.loadMyPublicKey(myPublicKeyPEM);
    crypto.loadTheirPublicKey(theirPublicKeyPEM);
    
    // Decrypt the received message
    std::string decryptedMessage = crypto.decryptMessage(encryptedMessage);
    std::cout << "Decrypted message: " << decryptedMessage << std::endl;
    
    // Encrypt the message to send
    std::string encryptedResponse = crypto.encryptMessage(messageToEncrypt);
    std::cout << "Encrypted response: " << encryptedResponse << std::endl;
}

// These functions will be called externally but demonstrate how to use the classes
void demonstrateUsage() {
    // First part: password guessing
    runPasswordGuesser();
    
    // Second part: public key cryptography
    // Example keys (in real use, these would be provided externally)
    std::string myPublicKeyPEM = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----";
    std::string myPrivateKeyPEM = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----";
    std::string theirPublicKeyPEM = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----";
    
    // Example message (in real use, this would be provided externally)
    std::string encryptedMessage = "ENCRYPTED_BASE64_MESSAGE"; 
    std::string messageToEncrypt = "Hello, this is a test message";
    
    loadKeysAndHandleCrypto(myPublicKeyPEM, myPrivateKeyPEM, theirPublicKeyPEM, 
                           encryptedMessage, messageToEncrypt);
}
