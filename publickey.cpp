#include <gmpxx.h>
#include <stdexcept>
#include <utility>

// This is just a convenient name for the key pair
typedef std::pair<mpz_class, mpz_class> keypair;

// Test harness provides the hash function that we will use for
// signature verification. We are using tiny SHA values here
// to keep our messages small so that we can use smaller primes
// in our key generation sequence.
uint16_t sha16(const mpz_class& key);

// Efficient modular exponentiation: base ** exponent mod modulus
mpz_class power_mod(mpz_class base, mpz_class exponent, const mpz_class& modulus) {
    mpz_class result(1);
    base = base % modulus;
    while (exponent > 0) {
        if (mpz_odd_p(exponent.get_mpz_t())) {
            result = (result * base) % modulus;
        }
        exponent /= 2;
        base = (base * base) % modulus;
    }
    return result;
}

// Modular multiplicative inverse
mpz_class modular_multiplicative_inverse(const mpz_class& a, const mpz_class& b) {
    mpz_class result;
    if (!mpz_invert(result.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t())) {
        throw std::runtime_error("Modular inverse does not exist");
    }
    return result;
}

// Save your private key and the last public key you sent me
mpz_class private_key;
keypair public_key;

// Key generation function
keypair create_keys(const mpz_class& p, const mpz_class& q) {
    mpz_class n = p * q;
    mpz_class phi = (p - 1) * (q - 1);
    mpz_class e(65537); // Commonly used public exponent
    mpz_class d = modular_multiplicative_inverse(e, phi);

    public_key = {e, n};
    private_key = d;

    return public_key;
}

// Message validation function
mpz_class validate(const mpz_class& cypher, const mpz_class& signature, const keypair& pats_public_key) {
    mpz_class decoded_message = power_mod(cypher, private_key, public_key.second);
    mpz_class decoded_hash = power_mod(signature, pats_public_key.first, pats_public_key.second);

    if (sha16(decoded_message) != decoded_hash.get_ui()) {
        return power_mod(mpz_class('f'), pats_public_key.first, pats_public_key.second);
    }

    return power_mod(mpz_class(mpz_even_p(decoded_message.get_mpz_t()) ? 'e' : 'o'), pats_public_key.first, pats_public_key.second);
}
