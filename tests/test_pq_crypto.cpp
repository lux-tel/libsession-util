// Pars Network PQ Crypto Unit Tests

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_approx.hpp>

#include "session/pq/pq_crypto.hpp"

#include <string>
#include <vector>

using namespace session::pq;

TEST_CASE("PQ Crypto Initialization", "[pq][init]") {
    REQUIRE(init());
}

TEST_CASE("ML-KEM-768 Key Generation", "[pq][mlkem]") {
    auto kp = mlkem768_keygen();
    REQUIRE(kp.has_value());
    REQUIRE(kp->public_key.size() == MLKEM768_PUBLIC_KEY_SIZE);
    REQUIRE(kp->secret_key.size() == MLKEM768_SECRET_KEY_SIZE);

    // Keys should be non-zero
    bool pk_nonzero = false;
    for (auto b : kp->public_key) {
        if (b != 0) { pk_nonzero = true; break; }
    }
    REQUIRE(pk_nonzero);
}

TEST_CASE("ML-DSA-65 Key Generation", "[pq][mldsa]") {
    auto kp = mldsa65_keygen();
    REQUIRE(kp.has_value());
    REQUIRE(kp->public_key.size() == MLDSA65_PUBLIC_KEY_SIZE);
    REQUIRE(kp->secret_key.size() == MLDSA65_SECRET_KEY_SIZE);

    // Keys should be non-zero
    bool pk_nonzero = false;
    for (auto b : kp->public_key) {
        if (b != 0) { pk_nonzero = true; break; }
    }
    REQUIRE(pk_nonzero);
}

TEST_CASE("Pars Identity Generation", "[pq][identity]") {
    auto identity = generate_pars_identity();
    REQUIRE(identity.has_value());

    // Check Session ID format
    REQUIRE(identity->session_id.size() == 66);
    REQUIRE(identity->session_id.substr(0, 2) == "07");
    REQUIRE(is_pars_session_id(identity->session_id));
    REQUIRE_FALSE(is_legacy_session_id(identity->session_id));

    // Two identities should have different session IDs
    auto identity2 = generate_pars_identity();
    REQUIRE(identity2.has_value());
    REQUIRE(identity->session_id != identity2->session_id);
}

TEST_CASE("ML-KEM-768 Encapsulation/Decapsulation", "[pq][mlkem][kem]") {
    auto kp = mlkem768_keygen();
    REQUIRE(kp.has_value());

    // Encapsulate
    auto encaps = mlkem768_encapsulate(kp->public_key);
    REQUIRE(encaps.has_value());
    REQUIRE(encaps->ciphertext.size() == MLKEM768_CIPHERTEXT_SIZE);
    REQUIRE(encaps->secret.size() == MLKEM768_SHARED_SECRET_SIZE);

    // Decapsulate
    auto decaps = mlkem768_decapsulate(encaps->ciphertext, kp->secret_key);
    REQUIRE(decaps.has_value());

    // Shared secrets should match
    REQUIRE(encaps->secret == *decaps);
}

TEST_CASE("ML-DSA-65 Sign/Verify", "[pq][mldsa][sig]") {
    auto kp = mldsa65_keygen();
    REQUIRE(kp.has_value());

    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o', ' ', 'P', 'a', 'r', 's', '!'};

    // Sign
    auto sig = mldsa65_sign(message, kp->secret_key);
    REQUIRE(sig.has_value());
    REQUIRE(sig->size() == MLDSA65_SIGNATURE_SIZE);

    // Verify (should succeed)
    REQUIRE(mldsa65_verify(message, *sig, kp->public_key));

    // Modify message - verify should fail
    message[0] = 'X';
    REQUIRE_FALSE(mldsa65_verify(message, *sig, kp->public_key));
}

TEST_CASE("Pars E2E Encrypt/Decrypt", "[pq][e2e]") {
    // Generate sender and recipient identities
    auto sender = generate_pars_identity();
    auto recipient = generate_pars_identity();
    REQUIRE(sender.has_value());
    REQUIRE(recipient.has_value());

    std::string message = "Hello from Pars Network! This is a post-quantum secure message.";
    std::vector<uint8_t> plaintext(message.begin(), message.end());

    // Encrypt
    auto encrypted = pars_encrypt(
        plaintext,
        sender->dsa.secret_key,
        sender->dsa.public_key,
        recipient->kem.public_key);
    REQUIRE(encrypted.has_value());

    // Encrypted should be larger due to PQ overhead
    INFO("Plaintext size: " << plaintext.size());
    INFO("Encrypted size: " << encrypted->size());
    REQUIRE(encrypted->size() > plaintext.size() + 6000);  // ~6KB PQ overhead

    // Decrypt
    auto decrypted = pars_decrypt(
        *encrypted,
        recipient->kem.secret_key,
        sender->dsa.public_key);
    REQUIRE(decrypted.has_value());

    // Should match original
    REQUIRE(*decrypted == plaintext);
}

TEST_CASE("Pars E2E - Wrong Sender Key Fails", "[pq][e2e][security]") {
    auto sender = generate_pars_identity();
    auto recipient = generate_pars_identity();
    auto attacker = generate_pars_identity();
    REQUIRE(sender.has_value());
    REQUIRE(recipient.has_value());
    REQUIRE(attacker.has_value());

    std::string message = "Secret message";
    std::vector<uint8_t> plaintext(message.begin(), message.end());

    // Encrypt from sender to recipient
    auto encrypted = pars_encrypt(
        plaintext,
        sender->dsa.secret_key,
        sender->dsa.public_key,
        recipient->kem.public_key);
    REQUIRE(encrypted.has_value());

    // Try to decrypt with wrong sender key - should fail
    auto decrypted = pars_decrypt(
        *encrypted,
        recipient->kem.secret_key,
        attacker->dsa.public_key);  // Wrong key!
    REQUIRE_FALSE(decrypted.has_value());
}

TEST_CASE("Pars E2E - Wrong Recipient Key Fails", "[pq][e2e][security]") {
    auto sender = generate_pars_identity();
    auto recipient = generate_pars_identity();
    auto attacker = generate_pars_identity();
    REQUIRE(sender.has_value());
    REQUIRE(recipient.has_value());
    REQUIRE(attacker.has_value());

    std::string message = "Secret message";
    std::vector<uint8_t> plaintext(message.begin(), message.end());

    // Encrypt from sender to recipient
    auto encrypted = pars_encrypt(
        plaintext,
        sender->dsa.secret_key,
        sender->dsa.public_key,
        recipient->kem.public_key);
    REQUIRE(encrypted.has_value());

    // Try to decrypt with attacker's key - should fail
    auto decrypted = pars_decrypt(
        *encrypted,
        attacker->kem.secret_key,  // Wrong key!
        sender->dsa.public_key);
    REQUIRE_FALSE(decrypted.has_value());
}

TEST_CASE("Session ID Format", "[pq][sessionid]") {
    REQUIRE(is_pars_session_id("07" + std::string(64, 'a')));
    REQUIRE_FALSE(is_pars_session_id("05" + std::string(64, 'a')));
    REQUIRE_FALSE(is_pars_session_id("07" + std::string(63, 'a')));
    REQUIRE_FALSE(is_pars_session_id(""));

    REQUIRE(is_legacy_session_id("05" + std::string(64, 'a')));
    REQUIRE_FALSE(is_legacy_session_id("07" + std::string(64, 'a')));
}

TEST_CASE("Performance - Key Generation", "[pq][perf]") {
    // Generate 10 keypairs and ensure it completes in reasonable time
    for (int i = 0; i < 10; i++) {
        auto kem = mlkem768_keygen();
        auto dsa = mldsa65_keygen();
        REQUIRE(kem.has_value());
        REQUIRE(dsa.has_value());
    }
}

TEST_CASE("Performance - Encrypt/Decrypt", "[pq][perf]") {
    auto sender = generate_pars_identity();
    auto recipient = generate_pars_identity();
    REQUIRE(sender.has_value());
    REQUIRE(recipient.has_value());

    std::string message = "Benchmark message for Pars Network performance testing.";
    std::vector<uint8_t> plaintext(message.begin(), message.end());

    // Encrypt/decrypt 100 times
    for (int i = 0; i < 100; i++) {
        auto encrypted = pars_encrypt(
            plaintext,
            sender->dsa.secret_key,
            sender->dsa.public_key,
            recipient->kem.public_key);
        REQUIRE(encrypted.has_value());

        auto decrypted = pars_decrypt(
            *encrypted,
            recipient->kem.secret_key,
            sender->dsa.public_key);
        REQUIRE(decrypted.has_value());
        REQUIRE(*decrypted == plaintext);
    }
}
