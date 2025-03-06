#include <gmpxx.h>
#include <stdexcept>
#include <utility>

// This is just a convenient name for the key pair
typedef std::pair<mpz_class, mpz_class> keypair;

// Test harness provides the hash function that we will use for
// signature verification. We are using tiny SHA values here
to keep our messages small so that we can use smaller primes
// in our key generation sequence.
uint16_t sha16(const mpz_class& key);

// It is often better if we are going to do base ** exponent mod modulus
// to do it in a single operation to keep the numbers from getting too big
// Not just true here, but we can use the same idea for normal integers to
// help keep values in range. There are a lot of articles on how to do this
// Find one and translate it to work with Gnu Multi-precision numbers
// Hint: To check if the exponent is odd, use
//   mpz_odd_p(exponent.get_mpz_t())) {
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

// GnuMP has already written this for you... it's in the original C interface
// though... Wrapped it to make it easier to call in C++
mpz_class modular_multiplicative_inverse(const mpz_class& a, const mpz_class& b) {
    mpz_class result;
    if (not mpz_invert(result.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t())) {
        throw std::runtime_error("domain error");
    }
    return result;
}

// Save your private key and the last public key you sent me
mpz_class private_key;
keypair public_key;

keypair create_keys(const mpz_class& p, const mpz_class& q) {
    mpz_class n = p * q;
    mpz_class phi = (p - 1) * (q - 1);
    mpz_class e(65537);
    mpz_class d = modular_multiplicative_inverse(e, phi);

    public_key = {e, n};
    private_key = d;

    return public_key;
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
    mpz_class decoded_message = power_mod(cypher, private_key, public_key.second);
    mpz_class decoded_hash = power_mod(signature, pats_public_key.first, pats_public_key.second);

    if (sha16(decoded_message) != decoded_hash.get_ui()) {
        return power_mod(mpz_class('f'), pats_public_key.first, pats_public_key.second);
    }

    return power_mod(mpz_class(mpz_even_p(decoded_message.get_mpz_t()) ? 'e' : 'o'), pats_public_key.first, pats_public_key.second);
}
