#include <gmpxx.h>
#include <unordered_set>
#include <stdexcept>
#include <string>
#include <utility>

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
typedef std::pair<mpz_class, mpz_class> keypair;

// SHA16 hash function (simplified for this lab)
uint16_t sha16(const mpz_class& key) {
    // Simulate a 16-bit hash by taking the lower 16 bits of the key
    return static_cast<uint16_t>(key.get_ui() & 0xFFFF);
}

// Modular exponentiation: base^exponent mod modulus
mpz_class power_mod(mpz_class base, mpz_class exponent, const mpz_class& modulus) {
    mpz_class result(1);
    base = base % modulus;
    while (exponent > 0) {
        if (mpz_odd_p(exponent.get_mpz_t())) {
            result = result * base % modulus;
        }
        exponent = exponent / 2;
        base = base * base % modulus;
    }
    return result;
}

// Modular multiplicative inverse
mpz_class modular_multiplicative_inverse(const mpz_class& a, const mpz_class& b) {
    mpz_class result;
    if (!mpz_invert(result.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t())) {
        throw std::runtime_error("domain error");
    }
    return result;
}

// Save your private key and the last public key you sent me
mpz_class private_key;
keypair public_key;

// Generate RSA key pair
keypair create_keys(const mpz_class& p, const mpz_class& q) {
    mpz_class n = p * q;
    mpz_class phi = (p - 1) * (q - 1);
    mpz_class e = 65537; // Common choice for public exponent
    mpz_class d = modular_multiplicative_inverse(e, phi);

    private_key = d;
    public_key = keypair(e, n);

    return public_key;
}

// Validate a message and its signature
mpz_class validate(const mpz_class& cypher, const mpz_class& signature, const keypair& pats_public_key) {
    // Decrypt the cypher using your private key
    mpz_class decrypted = power_mod(cypher, private_key, public_key.second);

    // Decrypt the signature using Pat's public key
    mpz_class recovered_hash = power_mod(signature, pats_public_key.first, pats_public_key.second);

    // Compute the hash of the decrypted message
    uint16_t computed_hash = sha16(decrypted);

    // Check if the recovered hash matches the computed hash
    if (recovered_hash.get_ui() != computed_hash) {
        // Forgery detected
        return mpz_class("f"); // Return 'f' for forgery
    }

    // Check if the decrypted message is even or odd
    if (mpz_even_p(decrypted.get_mpz_t())) {
        return mpz_class("e"); // Return 'e' for even
    } else {
        return mpz_class("o"); // Return 'o' for odd
    }
}
