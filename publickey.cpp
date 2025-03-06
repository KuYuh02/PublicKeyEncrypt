#include <iostream>
#include <string>
#include <vector>
#include <unordered_set>
#include <algorithm>
#include <random>
#include <gmpxx.h>

// External function that we'll call for password guessing
extern int guess(const std::string& password);

// This is just a convenient name for the key pair
typedef std::pair<mpz_class,mpz_class> keypair;

// Extern function declaration (provided by test harness)
extern uint16_t sha16(const mpz_class& key);

// Save your private key and the last public key you sent me
mpz_class private_key;
keypair public_key;

// Password guessing section
// -------------------------

// Character sets for password generation
const std::string LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
const std::string DIGITS = "0123456789";
const std::string SPECIAL = "-=.,/";
const std::string ALL_CHARS = LOWERCASE + DIGITS + SPECIAL;

// Random number generator
std::mt19937 rng(std::random_device{}());

// Function to generate common passwords
std::vector<std::string> generateCommonPasswords() {
    std::vector<std::string> passwords;
    
    // Common patterns
    passwords.push_back("123456");
    passwords.push_back("password");
    passwords.push_back("qwerty");
    passwords.push_back("abc123");
    passwords.push_back("letmein");
    passwords.push_back("monkey");
    passwords.push_back("111111");
    passwords.push_back("dragon");
    passwords.push_back("baseball");
    passwords.push_back("football");
    passwords.push_back("shadow");
    passwords.push_back("master");
    passwords.push_back("666666");
    passwords.push_back("qwertyui");
    passwords.push_back("123123");
    passwords.push_back("654321");
    passwords.push_back("jordan");
    passwords.push_back("harley");
    passwords.push_back("ranger");
    passwords.push_back("soccer");
    
    // Years and repeating digits
    for (int i = 2000; i <= 2024; i++) {
        std::string year = std::to_string(i);
        if (year.length() == 6) passwords.push_back(year);
        if (year.length() < 6) {
            passwords.push_back(year + std::string(6 - year.length(), '0'));
            passwords.push_back(std::string(6 - year.length(), '0') + year);
        }
    }
    
    // Repeating characters
    for (char c : ALL_CHARS) {
        passwords.push_back(std::string(6, c));
    }
    
    return passwords;
}

// Function to generate classmate-related passwords
std::vector<std::string> generateClassmatePasswords() {
    std::vector<std::string> passwords;
    
    // Course-related terms that might be used by classmates
    std::vector<std::string> courseTerms = {
        "cs", "cpp", "java", "code", "prog", "algo", 
        "class", "lab", "final", "exam", "term", "proj"
    };
    
    // Common student patterns
    for (const auto& term : courseTerms) {
        for (int i = 100; i <= 499; i++) {
            std::string pwd = term + std::to_string(i);
            if (pwd.length() <= 6) {
                passwords.push_back(pwd);
                if (pwd.length() < 6) {
                    passwords.push_back(pwd + std::string(6 - pwd.length(), '0'));
                }
            }
        }
        // Try with special characters
        for (char special : SPECIAL) {
            std::string pwd = term + special + "101";
            if (pwd.length() <= 6) {
                passwords.push_back(pwd);
                if (pwd.length() < 6) {
                    passwords.push_back(pwd + std::string(6 - pwd.length(), '1'));
                }
            }
        }
    }
    
    // School year combinations
    std::vector<std::string> semesters = {"fall", "spr", "win", "sum"};
    std::vector<std::string> years = {"22", "23", "24"};
    
    for (const auto& sem : semesters) {
        for (const auto& yr : years) {
            std::string pwd = sem + yr;
            if (pwd.length() <= 6) {
                passwords.push_back(pwd);
                if (pwd.length() < 6) {
                    passwords.push_back(pwd + std::string(6 - pwd.length(), '!'));
                }
            }
        }
    }
    
    return passwords;
}

// Generate dictionary-based passwords
std::vector<std::string> generateDictionaryPasswords() {
    std::vector<std::string> passwords;
    
    // Short words that might be used in passwords
    std::vector<std::string> words = {
        "pass", "word", "user", "admin", "root", "login", "test", 
        "home", "work", "name", "game", "love", "best", "cool", 
        "hack", "code", "data", "info", "web", "net", "key", "red",
        "blue", "gold", "sun", "moon", "star", "fire", "ice", "dog",
        "cat", "dark", "light", "one", "two", "win", "top", "max"
    };
    
    for (const auto& word : words) {
        if (word.length() == 6) {
            passwords.push_back(word);
        } 
        else if (word.length() < 6) {
            // Add digits to make length 6
            for (int i = 0; i <= 9999; i++) {
                std::string suffix = std::to_string(i);
                if (word.length() + suffix.length() == 6) {
                    passwords.push_back(word + suffix);
                }
                // Try with special chars
                for (char special : SPECIAL) {
                    if (word.length() + suffix.length() + 1 == 6) {
                        passwords.push_back(word + special + suffix);
                        passwords.push_back(word + suffix + special);
                    }
                }
            }
        }
    }
    
    return passwords;
}

// Generate random passwords
std::string generateRandomPassword() {
    std::string password;
    std::uniform_int_distribution<int> dist(0, ALL_CHARS.size() - 1);
    
    for (int i = 0; i < 6; i++) {
        password += ALL_CHARS[dist(rng)];
    }
    
    return password;
}

// Main password guessing function
void guessPasswords() {
    std::unordered_set<std::string> attemptedPasswords;
    int guessCount = 0;
    
    // Generate password lists
    std::vector<std::string> commonPasswords = generateCommonPasswords();
    std::vector<std::string> classmatePasswords = generateClassmatePasswords();
    std::vector<std::string> dictionaryPasswords = generateDictionaryPasswords();
    
    // 1. Try classmate passwords first (higher point value)
    for (const auto& pwd : classmatePasswords) {
        if (guessCount >= 1000000) break;
        if (attemptedPasswords.find(pwd) == attemptedPasswords.end()) {
            guess(pwd);
            attemptedPasswords.insert(pwd);
            guessCount++;
        }
    }
    
    // 2. Try common passwords
    for (const auto& pwd : commonPasswords) {
        if (guessCount >= 1000000) break;
        if (attemptedPasswords.find(pwd) == attemptedPasswords.end()) {
            guess(pwd);
            attemptedPasswords.insert(pwd);
            guessCount++;
        }
    }
    
    // 3. Try dictionary-based passwords
    for (const auto& pwd : dictionaryPasswords) {
        if (guessCount >= 1000000) break;
        if (attemptedPasswords.find(pwd) == attemptedPasswords.end()) {
            guess(pwd);
            attemptedPasswords.insert(pwd);
            guessCount++;
        }
    }
    
    // 4. Fill remaining guesses with random passwords
    while (guessCount < 1000000) {
        std::string randomPwd = generateRandomPassword();
        if (attemptedPasswords.find(randomPwd) == attemptedPasswords.end()) {
            guess(randomPwd);
            attemptedPasswords.insert(randomPwd);
            guessCount++;
        }
    }
}

// Public Key Cryptography section
// -------------------------------

// It is often better if we are going to do base ** exponent mod modulus
// to do it in a single operation to keep the numbers from getting too big
mpz_class power_mod(mpz_class base, mpz_class exponent, const mpz_class& modulus) {
  mpz_class result(1);
  base = base % modulus;
  while (exponent > 0) {
    if (mpz_odd_p(exponent.get_mpz_t())) {
      result = result*base % modulus;
    }
    exponent = exponent / 2;
    base = base*base % modulus;
  }

  return result;
}

// GnuMP has already written this for you... it's in the original C interface
// though... Wrapped it to make it easier to call in C++
mpz_class modular_multplicative_inverse(const mpz_class& a,const mpz_class& b) {
  mpz_class result;
  if (not mpz_invert(result.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t())) {
    throw std::runtime_error("domain error");
  }
  return result;
}

// Create RSA key pair
keypair create_keys(const mpz_class& p, const mpz_class& q) {
    // Calculate n = p * q
    mpz_class n = p * q;
    
    // Calculate Euler's totient function: φ(n) = (p-1) * (q-1)
    mpz_class phi = (p - 1) * (q - 1);
    
    // Choose e (public exponent): 1 < e < phi, gcd(e, phi) = 1
    // Common value is 65537 (0x10001), which is prime and has few 1 bits
    mpz_class e = 65537;
    
    // Calculate d (private exponent): d ≡ e^(-1) (mod φ(n))
    mpz_class d = modular_multplicative_inverse(e, phi);
    
    // Save the private key
    private_key = d;
    
    // Return the public key (n, e)
    public_key = std::make_pair(n, e);
    
    return public_key;
}

// Encrypt a message using the recipient's public key
mpz_class encrypt(const mpz_class& message, const keypair& recipient_public_key) {
    mpz_class n = recipient_public_key.first;
    mpz_class e = recipient_public_key.second;
    
    // c = m^e mod n
    return power_mod(message, e, n);
}

// Decrypt a message using our private key
mpz_class decrypt(const mpz_class& cypher) {
    mpz_class n = public_key.first;
    mpz_class d = private_key;
    
    // m = c^d mod n
    return power_mod(cypher, d, n);
}

// Sign a message using our private key
mpz_class sign(const mpz_class& message) {
    mpz_class n = public_key.first;
    mpz_class d = private_key;
    
    // signature = message^d mod n
    return power_mod(message, d, n);
}

// Verify a signature using the sender's public key
bool verify(const mpz_class& message, const mpz_class& signature, const keypair& sender_public_key) {
    mpz_class n = sender_public_key.first;
    mpz_class e = sender_public_key.second;
    
    // Calculate message' = signature^e mod n
    mpz_class calculated_message = power_mod(signature, e, n);
    
    // Verify that message' == message
    return calculated_message == message;
}

// Validate a message and signature
mpz_class validate(const mpz_class& cypher, const mpz_class& signature, const keypair& pats_public_key) {
    // First decrypt the cypher using our private key
    mpz_class message = decrypt(cypher);
    
    // Compute the hash of the decrypted message
    uint16_t message_hash = sha16(message);
    
    // Convert hash to mpz_class for verification
    mpz_class hash_value(message_hash);
    
    // Verify that the signature is valid using Pat's public key
    if (!verify(hash_value, signature, pats_public_key)) {
        // Forgery detected - encode 'f' using Pat's public key
        mpz_class response('f');
        return encrypt(response, pats_public_key);
    }
    
    // Message is authentic - determine if it's even or odd
    char response;
    if (message % 2 == 0) {
        // Even number - encode 'e'
        response = 'e';
    } else {
        // Odd number - encode 'o'
        response = 'o';
    }
    
    // Encrypt the response using Pat's public key
    return encrypt(mpz_class(response), pats_public_key);
}
