#include <gmpxx.h>
#include <string>
#include <random>
#include <unordered_set>

// Simulated database of passwords
std::unordered_set<std::string> password_database = {
    "abc123", "password", "123456", "qwerty", "letmein", "admin123"
};

// Simulated database of classmates' passwords
std::unordered_set<std::string> classmates_passwords = {
    "classmate1", "classmate2", "classmate3"
};

// Function to generate a random password
std::string generate_random_password() {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789-=.,/";
    static std::mt19937 rng(std::random_device{}());
    static std::uniform_int_distribution<size_t> dist(0, sizeof(charset) - 2);

    std::string password;
    for (int i = 0; i < 6; ++i) {
        password += charset[dist(rng)];
    }
    return password;
}

// Function to guess passwords
int guess() {
    static int counter = 0;
    int points = 0;

    for (int i = 0; i < 1000000; ++i) {
        std::string password = generate_random_password();
        if (password_database.find(password) != password_database.end()) {
            points += 1;
            if (classmates_passwords.find(password) != classmates_passwords.end()) {
                points += 9; // Additional 9 points for classmates' passwords
            }
        }
    }

    return points;
}
// Save your private key and the last public key you sent me
mpz_class private_key;
keypair public_key;

// Function to create keys
keypair create_keys(const mpz_class& p, const mpz_class& q) {
    mpz_class n = p * q;
    mpz_class phi = (p - 1) * (q - 1);

    // Choose a public key exponent e (typically 65537)
    mpz_class e = 65537;

    // Compute the private key exponent d
    mpz_class d = modular_multplicative_inverse(e, phi);

    // Save the private key
    private_key = d;

    // Return the public key (e, n)
    return std::make_pair(e, n);
}

// Function to validate a message
mpz_class validate(const mpz_class& cypher, const mpz_class& signature, const keypair& pats_public_key) {
    mpz_class recovered_hash = power_mod(signature, pats_public_key.first, pats_public_key.second);
    mpz_class computed_hash = sha16(cypher);

    if (recovered_hash != computed_hash) {
        // Return 'f' for forgery
        return mpz_class('f');
    } else {
        // Check if the message is even or odd
        if (mpz_even_p(cypher.get_mpz_t())) {
            return mpz_class('e');
        } else {
            return mpz_class('o');
        }
    }
}

// Function to encrypt a message using the recipient's public key
mpz_class encrypt(const std::string& message, const keypair& public_key) {
    mpz_class m(message);
    return power_mod(m, public_key.first, public_key.second);
}

// Function to decrypt a message using your private key
std::string decrypt(const mpz_class& cypher) {
    mpz_class m = power_mod(cypher, private_key, public_key.second);
    return m.get_str();
}
