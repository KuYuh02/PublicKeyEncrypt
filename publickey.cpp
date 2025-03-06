#include <gmpxx.h>
#include <stdexcept>
#include <utility>

// Convenient name for the key pair
typedef std::pair<mpz_class, mpz_class> keypair;

// Test harness provides the hash function
uint16_t sha16(const mpz_class& key);

// Fast modular exponentiation
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

// Private key and last public key sent
mpz_class private_key;
keypair public_key;

// Key creation function
keypair create_keys(const mpz_class& p, const mpz_class& q) {
    mpz_class n = p * q;
    mpz_class phi = (p - 1) * (q - 1);

    mpz_class e(65537); // Commonly used prime for public exponent
    if (mpz_gcd_ui(nullptr, phi.get_mpz_t(), e.get_ui()) != 1) {
        throw std::runtime_error("Invalid e value");
    }

    mpz_class d = modular_multiplicative_inverse(e, phi);

    public_key = {e, n};
    private_key = d;

    return public_key;
}

// Message validation function
mpz_class validate(const mpz_class& cypher, const mpz_class& signature, const keypair& pats_public_key) {
    // Decrypt signature with Pat's public key to get the hash
    mpz_class decrypted_hash = power_mod(signature, pats_public_key.first, pats_public_key.second);

    // Compute the hash of the cypher
    mpz_class cypher_hash = sha16(cypher);

    // If hashes don't match, it's a forgery
    if (decrypted_hash != cypher_hash) {
        // Encrypt 'f' using Pat's public key
        return power_mod(mpz_class('f'), pats_public_key.first, pats_public_key.second);
    }

    // Determine if cypher is even or odd and respond accordingly
    char response;
    if (cypher % 2 == 0) {
        response = 'e';
    } else {
        response = 'o';
    }

    // Encrypt the response using Pat's public key
    return power_mod(mpz_class(response), pats_public_key.first, pats_public_key.second);
}
