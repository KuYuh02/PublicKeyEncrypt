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

// Key creation function - consistent format (n,e) for public key
keypair create_keys(const mpz_class& p, const mpz_class& q) {
  mpz_class n = p * q;
  mpz_class phi = (p - 1) * (q - 1);
  mpz_class e(65537); // Commonly used prime for public exponent
  
  if (mpz_gcd_ui(nullptr, phi.get_mpz_t(), e.get_ui()) != 1) {
    throw std::runtime_error("Invalid e value");
  }
  
  mpz_class d = modular_multiplicative_inverse(e, phi);
  public_key = std::make_pair(n, e); // Store as (n,e)
  private_key = d;
  
  return public_key;
}

// Fixed validation function
mpz_class validate(const mpz_class& cypher, const mpz_class& signature, const keypair& pats_public_key) {
  // Extract n and e from Pat's public key
  mpz_class n = pats_public_key.first;
  mpz_class e = pats_public_key.second;
  
  // Decrypt the signature using Pat's public key
  mpz_class decrypted_signature = power_mod(signature, e, n);
  
  // Decrypt the message using our private key
  mpz_class decrypted_message = power_mod(cypher, private_key, public_key.first);
  
  // Calculate hash of the decrypted message
  uint16_t calculated_hash = sha16(decrypted_message);
  
  // Check if the signature matches the hash
  if (decrypted_signature != calculated_hash) {
    // Forgery detected, send 'f'
    mpz_class response('f');
    // Encrypt with Pat's public key
    return power_mod(response, e, n);
  } else {
    // Valid message, check if even or odd
    char result = mpz_even_p(decrypted_message.get_mpz_t()) ? 'e' : 'o';
    mpz_class response(result);
    // Encrypt with Pat's public key
    return power_mod(response, e, n);
  }
}
