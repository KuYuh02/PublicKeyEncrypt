#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <algorithm>
#include <ctime>
#include <utility>
#include <cmath>

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

// Part 2: Public Key Cryptography
// Based on publickey2.cpp format from the image
class Cryptography {
private:
    // Based on the image, publickey2.cpp uses (n, e) format for public key
    // and uses mpz_class d for private key
    typedef std::pair<long long, long long> KeyPair;
    KeyPair public_key;  // Format: (n, e) as seen in image
    long long private_key;
    
    // Calculate modular multiplicative inverse
    long long modular_multiplicative_inverse(long long e, long long phi) {
        long long d = 0;
        long long x1 = 0;
        long long x2 = 1;
        long long y1 = 1;
        long long y2 = 0;
        long long temp_phi = phi;
        
        while (e > 0) {
            long long q = temp_phi / e;
            long long t = e;
            e = temp_phi % e;
            temp_phi = t;
            
            long long t1 = x2 - q * x1;
            x2 = x1;
            x1 = t1;
            
            long long t2 = y2 - q * y1;
            y2 = y1;
            y1 = t2;
        }
        
        if (temp_phi == 1) {
            d = y2;
        }
        
        if (d < 0) {
            d += phi;
        }
        
        return d;
    }
    
    // Modular exponentiation (power_mod from image)
    long long power_mod(long long base, long long exponent, long long modulus) {
        long long result = 1;
        base = base % modulus;
        
        while (exponent > 0) {
            if (exponent % 2 == 1) {
                result = (result * base) % modulus;
            }
            exponent = exponent >> 1;
            base = (base * base) % modulus;
        }
        
        return result;
    }
    
public:
    Cryptography() : private_key(0) {
        // Default constructor
    }
    
    // Load or set keys
    void setMyKeys(long long n, long long e, long long d) {
        // Set public key in (n, e) format as shown in image
        public_key = std::make_pair(n, e);
        
        // Set private key
        private_key = d;
    }
    
    void generateKeys(long long p, long long q) {
        // Calculate n
        long long n = p * q;
        
        // Calculate Euler's totient function φ(n)
        long long phi = (p - 1) * (q - 1);
        
        // Choose e (common value is 65537)
        long long e = 65537;
        
        // Calculate d (private key) using modular_multiplicative_inverse
        long long d = modular_multiplicative_inverse(e, phi);
        private_key = d;
        
        // Set public key in (n, e) format as per image
        public_key = std::make_pair(n, e);
    }
    
    void setTheirPublicKey(long long n, long long e) {
        // We're setting someone else's public key for encryption
        public_key = std::make_pair(n, e);
    }
    
    // Decrypt a message using my private key
    // Based on image: power_mod(cypher, private_key, public_key.first)
    long long decrypt(long long ciphertext) {
        return power_mod(ciphertext, private_key, public_key.first);
    }
    
    // Encrypt a message using their public key
    // Based on image: power_mod(message, public_key.second, public_key.first)
    long long encrypt(long long plaintext) {
        return power_mod(plaintext, public_key.second, public_key.first);
    }
    
    // Verify a signature (based on image)
    bool verifySignature(long long message, long long signature, KeyPair their_public_key) {
        // In publickey2.cpp, verification uses:
        // power_mod(signature, pats_public_key.second, pats_public_key.first)
        long long decrypted_signature = power_mod(signature, their_public_key.second, their_public_key.first);
        return (decrypted_signature == message);
    }
    
    // Sign a message
    long long sign(long long message) {
        // In publickey2.cpp, signing uses private_key and n:
        // power_mod('f', private_key, public_key.first)
        return power_mod(message, private_key, public_key.first);
    }
    
    // Get public key
    KeyPair getPublicKey() const {
        return public_key;
    }
};

// Function prototype for the external guess function
extern bool guess(const std::string& password);

// The guess function will be called 1,000,000 times within a loop
// This will be implemented by the assignment framework
bool guess(const std::string& password) {
    // This is just a placeholder - the actual implementation
    // will be provided by the assignment framework
    return false;
}
