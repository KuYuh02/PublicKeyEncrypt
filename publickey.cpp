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

// Test harness provides the hash function that we will use for
// signature verification. We are using tiny SHA values here
// to keep our messages small so that we can use smaller primes
// in our key generation sequence.
extern uint16_t sha16(const mpz_class& key);

// It is often better if we are going to do base ** exponent mod modulus
// to do it in a single operation to keep the numbers from getting too big
// Not just true here, but we can use the same idea for normal integers to
// help keep values in range.  There are a lot of articles on how to do this
// Find one and translate it to work with Gnu Multi-precission numbers
// Hint: To check if the exponent is odd, use
//  mpz_odd_p(exponent.get_mpz_t())) {  
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

// Save your private key and the last public key you sent me
mpz_class private_key;
keypair public_key;

// Character sets for password generation
const std::string LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
const std::string DIGITS = "0123456789";
const std::string SPECIAL = "-=.,/";
const std::string ALL_CHARS = LOWERCASE + DIGITS + SPECIAL;

// Random number generator
std::mt19937 rng(std::random_device{}());

// Create RSA key pair
keypair create_keys(const mpz_class& p, const mpz_class& q) {
    // Calculate n = p * q
    mpz_class n = p * q;
    
    // Calculate Euler's totient function: φ(n) = (p-1) * (q-1)
    mpz_class phi = (p - 1) * (q - 1);
    
    // Choose e (public exponent): 1 < e < phi, gcd(e, phi) = 1
    // Common value is 65537 (0x10001), which is prime and has few 1 bits
    mpz_class e = 65537;
    
    // Make sure e and phi are coprime
    mpz_class gcd;
    mpz_gcd(gcd.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t());
    
    // If gcd != 1, find another e
    while (gcd != 1) {
        e = e + 2;  // Keep e odd
        mpz_gcd(gcd.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t());
    }
    
    // Calculate d (private exponent): d ≡ e^(-1) (mod φ(n))
    mpz_class d = modular_multplicative_inverse(e, phi);
    
    // Save the private key
    private_key = d;
    
    // Return the public key (n, e)
    public_key = std::make_pair(n, e);
    
    return public_key;
}

// Decrypt a message using our private key
mpz_class decrypt(const mpz_class& cypher) {
    mpz_class n = public_key.first;
    // Use our private key
    return power_mod(cypher, private_key, n);
}

// Encrypt a message using a recipient's public key
mpz_class encrypt(const mpz_class& message, const keypair& recipient_public_key) {
    mpz_class n = recipient_public_key.first;
    mpz_class e = recipient_public_key.second;
    
    // c = m^e mod n
    return power_mod(message, e, n);
}

// You will write a message validator. I will send you a message encoded with
// your public key... I computed the SHA16 hash of the message and encoded it
// using my PRIVATE key. So, you can recover the hash using my PUBLIC key.
// If the hash doesn't match hash(decoded cypher), it is a forgery!! Encode
// the message 'f' to let me know you intercepted a bogus message. Otherwise,
// if I did sign this message, send back 'e' to let me know that it was an even
// number or 'o' to let me know it was an odd. Encode it using my public key
// so I can decode it securely.
mpz_class validate(const mpz_class& cypher, const mpz_class& signature, const keypair& pats_public_key) {
    // Decrypt the message using our private key
    mpz_class message = decrypt(cypher);
    
    // Compute the hash of the decrypted message
    uint16_t message_hash = sha16(message);
    
    // Recover the hash from the signature using Pat's public key
    mpz_class verified_hash = power_mod(signature, pats_public_key.second, pats_public_key.first);
    
    // Check if the hash matches
    if (verified_hash != message_hash) {
        // Forgery detected - encode 'f' using Pat's public key
        mpz_class forgery_response('f');
        return encrypt(forgery_response, pats_public_key);
    }
    
    // Message is authentic - check if it's even or odd
    char response_char;
    if (message % 2 == 0) {
        // Even
        response_char = 'e';
    } else {
        // Odd
        response_char = 'o';
    }
    
    // Encrypt response using Pat's public key
    mpz_class response(response_char);
    return encrypt(response, pats_public_key);
}

// Function to generate passwords based on common patterns
void generateCommonPasswords(std::vector<std::string>& passwords) {
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
    passwords.push_back("123123");
    passwords.push_back("654321");
    passwords.push_back("jordan");
    passwords.push_back("harley");
    passwords.push_back("ranger");
    passwords.push_back("soccer");
    
    // Sequential patterns
    for (char start : LOWERCASE) {
        std::string seq;
        for (int i = 0; i < 6; i++) {
            char c = start + i;
            if (c <= 'z') seq += c;
            else break;
        }
        if (seq.length() == 6) passwords.push_back(seq);
    }
    
    // Repeating characters
    for (char c : ALL_CHARS) {
        passwords.push_back(std::string(6, c));
    }
    
    // Years
    for (int year = 1950; year <= 2024; year++) {
        passwords.push_back(std::to_string(year));
    }
}

// Function to generate classmate-related passwords
void generateClassmatePasswords(std::vector<std::string>& passwords) {
    // Course-related terms
    std::vector<std::string> prefixes = {
        "cs", "cpp", "java", "code", "prog", "algo", 
        "class", "lab", "final", "exam", "comp", "net"
    };
    
    // Common course numbers
    std::vector<std::string> numbers = {
        "101", "201", "301", "401", "100", "200", "300", "400",
        "123", "234", "345", "456", "111", "222", "333", "444"
    };
    
    // Combine course prefix with numbers
    for (const auto& prefix : prefixes) {
        for (const auto& num : numbers) {
            std::string pwd = prefix + num;
            if (pwd.length() <= 6) {
                passwords.push_back(pwd);
                if (pwd.length() < 6) {
                    passwords.push_back(pwd + std::string(6 - pwd.length(), '0'));
                }
            }
        }
    }
    
    // School-related terms with special chars
    for (const auto& prefix : prefixes) {
        for (char special : SPECIAL) {
            for (int i = 0; i <= 999; i++) {
                std::string num = std::to_string(i);
                while (num.length() < 3) num = "0" + num;
                
                std::string pwd = prefix + special + num;
                if (pwd.length() == 6) {
                    passwords.push_back(pwd);
                }
            }
        }
    }
    
    // Semester + year combinations
    std::vector<std::string> semesters = {"fall", "spr", "win", "sum"};
    std::vector<std::string> years = {"22", "23", "24", "25"};
    
    for (const auto& sem : semesters) {
        for (const auto& yr : years) {
            std::string pwd = sem + yr;
            if (pwd.length() <= 6) {
                passwords.push_back(pwd);
                if (pwd.length() < 6) {
                    passwords.push_back(pwd + std::string(6 - pwd.length(), '1'));
                }
            }
        }
    }
}

// Function to generate dictionary-based passwords
void generateWordPasswords(std::vector<std::string>& passwords) {
    // Common short words
    std::vector<std::string> words = {
        "pass", "word", "user", "admin", "root", "login", "test", 
        "home", "work", "name", "game", "love", "best", "cool", 
        "hack", "code", "data", "info", "web", "net", "key", "red",
        "blue", "gold", "sun", "moon", "star", "fire", "ice", "dog",
        "cat", "dark", "light", "one", "two", "win", "top", "max"
    };
    
    // Add words of exactly length 6
    for (const auto& word : words) {
        if (word.length() == 6) {
            passwords.push_back(word);
        }
    }
    
    // Add words with digits
    for (const auto& word : words) {
        if (word.length() < 6) {
            int digitsNeeded = 6 - word.length();
            if (digitsNeeded <= 4) {
                // Add all combinations of digits to make length 6
                int maxValue = 1;
                for (int i = 0; i < digitsNeeded; i++) {
                    maxValue *= 10;
                }
                
                for (int i = 0; i < maxValue; i++) {
                    std::string digits = std::to_string(i);
                    while (digits.length() < digitsNeeded) {
                        digits = "0" + digits;
                    }
                    passwords.push_back(word + digits);
                }
            }
        }
    }
    
    // Add words with special chars and digits
    for (const auto& word : words) {
        if (word.length() < 5) {
            for (char special : SPECIAL) {
                if (word.length() + 1 < 6) {
                    int digitsNeeded = 6 - word.length() - 1;
                    if (digitsNeeded <= 3) {
                        int maxValue = 1;
                        for (int i = 0; i < digitsNeeded; i++) {
                            maxValue *= 10;
                        }
                        
                        for (int i = 0; i < maxValue; i++) {
                            std::string digits = std::to_string(i);
                            while (digits.length() < digitsNeeded) {
                                digits = "0" + digits;
                            }
                            passwords.push_back(word + special + digits);
                            passwords.push_back(word + digits + special);
                        }
                    }
                }
            }
        }
    }
}

// Generate a random password
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
    std::unordered_set<std::string> attempted;
    std::vector<std::string> passwords;
    int guessCount = 0;
    
    // Generate classmate passwords (highest value)
    generateClassmatePasswords(passwords);
    
    // Generate common passwords
    generateCommonPasswords(passwords);
    
    // Generate dictionary-based passwords
    generateWordPasswords(passwords);
    
    // Make the guesses
    for (const std::string& pwd : passwords) {
        if (guessCount >= 1000000) break;
        
        // Skip passwords that don't match the criteria
        if (pwd.length() != 6) continue;
        
        // Check if valid characters
        bool validChars = true;
        for (char c : pwd) {
            if (LOWERCASE.find(c) == std::string::npos && 
                DIGITS.find(c) == std::string::npos && 
                SPECIAL.find(c) == std::string::npos) {
                validChars = false;
                break;
            }
        }
        if (!validChars) continue;
        
        // Make the guess if we haven't tried this password
        if (attempted.find(pwd) == attempted.end()) {
            guess(pwd);
            attempted.insert(pwd);
            guessCount++;
        }
    }
    
    // Fill remaining guesses with random passwords
    while (guessCount < 1000000) {
        std::string randPwd = generateRandomPassword();
        if (attempted.find(randPwd) == attempted.end()) {
            guess(randPwd);
            attempted.insert(randPwd);
            guessCount++;
        }
    }
}
