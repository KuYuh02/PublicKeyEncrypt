keypair create_keys(const mpz_class& p, const mpz_class& q) {
    // Compute n = p * q
    mpz_class n = p * q;
    
    // Compute Euler's totient function φ(n) = (p-1)(q-1)
    mpz_class phi = (p - 1) * (q - 1);
    
    // Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
    // Common choice is 65537 (2^16 + 1), but we'll use a smaller value for this example
    mpz_class e = 65537;
    
    // Make sure e is coprime with phi
    mpz_class gcd;
    mpz_gcd(gcd.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t());
    if (gcd != 1) {
        // Find another e if needed
        for (mpz_class i = 3; i < phi; i = i + 2) {
            mpz_gcd(gcd.get_mpz_t(), i.get_mpz_t(), phi.get_mpz_t());
            if (gcd == 1) {
                e = i;
                break;
            }
        }
    }
    
    // Compute d such that d*e ≡ 1 (mod φ(n))
    mpz_class d = modular_multplicative_inverse(e, phi);
    
    // Store private key
    private_key = d;
    
    // Return public key (n, e)
    public_key = std::make_pair(n, e);
    return public_key;
}

mpz_class validate(const mpz_class& cypher, const mpz_class& signature, const keypair& pats_public_key) {
    // Extract n and e from the public key
    mpz_class n = pats_public_key.first;
    mpz_class e = pats_public_key.second;
    
    // Decrypt the signature using Pat's public key to get the hash
    // signature^e mod n
    mpz_class decrypted_hash = power_mod(signature, e, n);
    
    // Decrypt the cypher using my private key
    mpz_class decrypted_message = power_mod(cypher, private_key, public_key.first);
    
    // Calculate the hash of the decrypted message
    uint16_t calculated_hash = sha16(decrypted_message);
    mpz_class hash_value(calculated_hash);
    
    // Verify if the decrypted hash matches the calculated hash
    if (decrypted_hash != hash_value) {
        // Message is a forgery, encode 'f' using Pat's public key
        mpz_class message('f');
        return power_mod(message, e, n);
    } else {
        // Message is authentic, check if it's even or odd
        char response = mpz_even_p(decrypted_message.get_mpz_t()) ? 'e' : 'o';
        mpz_class message(response);
        return power_mod(message, e, n);
    }
}
// Function to guess passwords
std::vector<std::string> generate_password_guesses(int count) {
    std::vector<std::string> guesses;
    
    // Common patterns
    std::vector<std::string> patterns = {
        "123456", "password", "qwerty", "abc123", "letmein",
        "monkey", "dragon", "baseball", "football", "hockey"
    };
    
    // Add some common patterns first
    for (const auto& pattern : patterns) {
        if (guesses.size() < count && pattern.length() == 6) {
            guesses.push_back(pattern);
        }
    }
    
    // Common name + digit patterns
    std::vector<std::string> names = {
        "john", "david", "mike", "chris", "bob", 
        "mary", "lisa", "anna", "amy", "kate"
    };
    
    for (const auto& name : names) {
        if (name.length() <= 4) {
            for (int i = 0; i <= 99; i++) {
                std::string pwd = name;
                if (i < 10) {
                    pwd += "0";
                }
                pwd += std::to_string(i);
                
                if (guesses.size() < count && pwd.length() == 6) {
                    guesses.push_back(pwd);
                }
            }
        }
    }
    
    // Year-based patterns (common birth years, graduation years)
    for (int year = 1950; year <= 2024; year++) {
        std::string yr = std::to_string(year);
        if (guesses.size() < count) {
            guesses.push_back(yr);
        }
    }
    
    // Month+Day combinations
    for (int month = 1; month <= 12; month++) {
        for (int day = 1; day <= 31; day++) {
            std::string mmdd;
            if (month < 10) mmdd += "0";
            mmdd += std::to_string(month);
            if (day < 10) mmdd += "0";
            mmdd += std::to_string(day);
            
            if (guesses.size() < count && mmdd.length() == 4) {
                // Add 19 or 20 prefix
                guesses.push_back("19" + mmdd);
                guesses.push_back("20" + mmdd);
            }
        }
    }
    
    // Sequential and repeating patterns
    std::vector<std::string> sequences = {
        "abcdef", "qwerty", "asdfgh", "zxcvbn", "123456", 
        "654321", "112233", "aabbcc", "ababab", "121212"
    };
    
    for (const auto& seq : sequences) {
        if (guesses.size() < count && seq.length() == 6) {
            guesses.push_back(seq);
        }
    }
    
    // Fill remaining with common patterns or random variations
    while (guesses.size() < count) {
        // Generate passwords with common words
        std::vector<std::string> words = {
            "pass", "word", "test", "user", "admin", 
            "root", "love", "hate", "game", "play"
        };
        
        for (const auto& word : words) {
            if (word.length() <= 4) {
                for (int i = 0; i <= 9999; i++) {
                    std::string suffix = std::to_string(i);
                    // Add leading zeros
                    while (word.length() + suffix.length() < 6) {
                        suffix = "0" + suffix;
                    }
                    
                    std::string pwd = word + suffix;
                    if (pwd.length() == 6 && guesses.size() < count) {
                        guesses.push_back(pwd);
                    }
                }
            }
        }
        
        // If we still need more, add some with special characters
        if (guesses.size() < count) {
            for (char c : std::string("-=.,/")) {
                for (const auto& name : names) {
                    if (name.length() == 5) {
                        std::string pwd = name + c;
                        if (guesses.size() < count) {
                            guesses.push_back(pwd);
                        }
                    }
                }
            }
        }
        
        // If we still don't have enough, generate some random ones
        if (guesses.size() < count) {
            static const char charset[] = 
                "abcdefghijklmnopqrstuvwxyz0123456789-=.,/";
            
            std::string random_pwd(6, ' ');
            for (int i = 0; i < 6; i++) {
                random_pwd[i] = charset[rand() % (sizeof(charset) - 1)];
            }
            
            guesses.push_back(random_pwd);
        }
    }
    
    return guesses;
}

// Function to guess passwords
void guess_passwords(int count) {
    std::vector<std::string> guesses = generate_password_guesses(count);
    
    // Call the provided guess function for each password
    for (const auto& pwd : guesses) {
        if (pwd.length() == 6) {
            guess(pwd);
        }
    }
}
