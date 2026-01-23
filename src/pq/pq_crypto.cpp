// Pars Network Post-Quantum Cryptography Implementation
// Uses liboqs (Open Quantum Safe) for NIST FIPS 203/204

#include "session/pq/pq_crypto.hpp"

#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>

#include <cstring>
#include <iomanip>
#include <sstream>

// TODO: Link against liboqs when available
// #include <oqs/oqs.h>

namespace session::pq {

namespace {

// Placeholder until liboqs is integrated
// These will be replaced with actual OQS calls

constexpr std::string_view BLAKE2B_PERSONALIZATION = "ParsSessionID";

std::string bytes_to_hex(std::span<const uint8_t> data) {
    std::ostringstream oss;
    for (uint8_t byte : data) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

}  // namespace

// =============================================================================
// Initialization
// =============================================================================

bool init() {
    // Initialize libsodium (for symmetric crypto)
    if (sodium_init() < 0) {
        return false;
    }

    // TODO: Initialize liboqs
    // OQS_init();

    return true;
}

// =============================================================================
// Key Generation
// =============================================================================

std::optional<MLKEMKeyPair> mlkem768_keygen() {
    MLKEMKeyPair kp;

    // TODO: Replace with actual liboqs call
    // OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    // if (!kem) return std::nullopt;
    //
    // if (OQS_KEM_keypair(kem, kp.public_key.data(), kp.secret_key.data()) != OQS_SUCCESS) {
    //     OQS_KEM_free(kem);
    //     return std::nullopt;
    // }
    // OQS_KEM_free(kem);

    // Placeholder: generate random bytes (NOT SECURE - FOR TESTING ONLY)
    randombytes_buf(kp.public_key.data(), kp.public_key.size());
    randombytes_buf(kp.secret_key.data(), kp.secret_key.size());

    return kp;
}

std::optional<MLDSAKeyPair> mldsa65_keygen() {
    MLDSAKeyPair kp;

    // TODO: Replace with actual liboqs call
    // OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    // if (!sig) return std::nullopt;
    //
    // if (OQS_SIG_keypair(sig, kp.public_key.data(), kp.secret_key.data()) != OQS_SUCCESS) {
    //     OQS_SIG_free(sig);
    //     return std::nullopt;
    // }
    // OQS_SIG_free(sig);

    // Placeholder: generate random bytes (NOT SECURE - FOR TESTING ONLY)
    randombytes_buf(kp.public_key.data(), kp.public_key.size());
    randombytes_buf(kp.secret_key.data(), kp.secret_key.size());

    return kp;
}

std::string derive_session_id(
    std::span<const uint8_t> kem_pk,
    std::span<const uint8_t> dsa_pk) {

    // Blake2b-256(kem_pk || dsa_pk) with personalization
    std::array<uint8_t, 32> hash;

    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init_salt_personal(
        &state,
        nullptr, 0,  // no key
        hash.size(),
        nullptr,     // no salt
        reinterpret_cast<const unsigned char*>(BLAKE2B_PERSONALIZATION.data()));

    crypto_generichash_blake2b_update(&state, kem_pk.data(), kem_pk.size());
    crypto_generichash_blake2b_update(&state, dsa_pk.data(), dsa_pk.size());
    crypto_generichash_blake2b_final(&state, hash.data(), hash.size());

    // Return "07" + hex(hash)
    return std::string(PARS_SESSION_ID_PREFIX) + bytes_to_hex(hash);
}

std::optional<ParsIdentity> generate_pars_identity() {
    auto kem = mlkem768_keygen();
    if (!kem) return std::nullopt;

    auto dsa = mldsa65_keygen();
    if (!dsa) return std::nullopt;

    ParsIdentity identity;
    identity.kem = std::move(*kem);
    identity.dsa = std::move(*dsa);
    identity.session_id = derive_session_id(
        identity.kem.public_key,
        identity.dsa.public_key);

    return identity;
}

// =============================================================================
// ML-KEM Key Encapsulation
// =============================================================================

std::optional<EncapsulationResult> mlkem768_encapsulate(
    std::span<const uint8_t> recipient_pk) {

    if (recipient_pk.size() != MLKEM768_PUBLIC_KEY_SIZE) {
        return std::nullopt;
    }

    EncapsulationResult result;

    // TODO: Replace with actual liboqs call
    // OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    // if (!kem) return std::nullopt;
    //
    // if (OQS_KEM_encaps(kem, result.ciphertext.data(), result.secret.data(),
    //                   recipient_pk.data()) != OQS_SUCCESS) {
    //     OQS_KEM_free(kem);
    //     return std::nullopt;
    // }
    // OQS_KEM_free(kem);

    // Placeholder: generate random ciphertext and shared secret
    randombytes_buf(result.ciphertext.data(), result.ciphertext.size());
    randombytes_buf(result.secret.data(), result.secret.size());

    return result;
}

std::optional<shared_secret> mlkem768_decapsulate(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> secret_key) {

    if (ciphertext.size() != MLKEM768_CIPHERTEXT_SIZE ||
        secret_key.size() != MLKEM768_SECRET_KEY_SIZE) {
        return std::nullopt;
    }

    shared_secret ss;

    // TODO: Replace with actual liboqs call
    // OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    // if (!kem) return std::nullopt;
    //
    // if (OQS_KEM_decaps(kem, ss.data(), ciphertext.data(),
    //                   secret_key.data()) != OQS_SUCCESS) {
    //     OQS_KEM_free(kem);
    //     return std::nullopt;
    // }
    // OQS_KEM_free(kem);

    // Placeholder: generate deterministic "shared secret" from ciphertext
    crypto_generichash_blake2b(ss.data(), ss.size(),
                               ciphertext.data(), ciphertext.size(),
                               secret_key.data(), 32);

    return ss;
}

// =============================================================================
// ML-DSA Signatures
// =============================================================================

std::optional<mldsa65_signature> mldsa65_sign(
    std::span<const uint8_t> message,
    std::span<const uint8_t> secret_key) {

    if (secret_key.size() != MLDSA65_SECRET_KEY_SIZE) {
        return std::nullopt;
    }

    mldsa65_signature sig;

    // TODO: Replace with actual liboqs call
    // OQS_SIG *dsa = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    // if (!dsa) return std::nullopt;
    //
    // size_t sig_len = 0;
    // if (OQS_SIG_sign(dsa, sig.data(), &sig_len,
    //                 message.data(), message.size(),
    //                 secret_key.data()) != OQS_SUCCESS) {
    //     OQS_SIG_free(dsa);
    //     return std::nullopt;
    // }
    // OQS_SIG_free(dsa);

    // Placeholder: HMAC-based "signature" (NOT SECURE - FOR TESTING ONLY)
    crypto_generichash_blake2b(sig.data(), 64,
                               message.data(), message.size(),
                               secret_key.data(), 32);
    // Fill rest with zeros
    std::memset(sig.data() + 64, 0, sig.size() - 64);

    return sig;
}

bool mldsa65_verify(
    std::span<const uint8_t> message,
    std::span<const uint8_t> signature,
    std::span<const uint8_t> public_key) {

    if (signature.size() != MLDSA65_SIGNATURE_SIZE ||
        public_key.size() != MLDSA65_PUBLIC_KEY_SIZE) {
        return false;
    }

    // TODO: Replace with actual liboqs call
    // OQS_SIG *dsa = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    // if (!dsa) return false;
    //
    // bool valid = OQS_SIG_verify(dsa, message.data(), message.size(),
    //                            signature.data(), signature.size(),
    //                            public_key.data()) == OQS_SUCCESS;
    // OQS_SIG_free(dsa);
    // return valid;

    // Placeholder: always return true (NOT SECURE - FOR TESTING ONLY)
    return true;
}

// =============================================================================
// Pars E2E Encryption Protocol
// =============================================================================

std::optional<std::vector<uint8_t>> pars_encrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> sender_dsa_sk,
    std::span<const uint8_t> sender_dsa_pk,
    std::span<const uint8_t> recipient_kem_pk) {

    // 1. ML-KEM encapsulate
    auto encaps = mlkem768_encapsulate(recipient_kem_pk);
    if (!encaps) return std::nullopt;

    // 2. Derive symmetric key: K = Blake2b(shared || sender_dsa_pk || recipient_kem_pk)
    std::array<uint8_t, 32> sym_key;
    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, nullptr, 0, sym_key.size());
    crypto_generichash_blake2b_update(&state, encaps->secret.data(), encaps->secret.size());
    crypto_generichash_blake2b_update(&state, sender_dsa_pk.data(), sender_dsa_pk.size());
    crypto_generichash_blake2b_update(&state, recipient_kem_pk.data(), recipient_kem_pk.size());
    crypto_generichash_blake2b_final(&state, sym_key.data(), sym_key.size());

    // 3. Encrypt with XChaCha20-Poly1305
    constexpr size_t NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    constexpr size_t TAG_SIZE = crypto_aead_xchacha20poly1305_ietf_ABYTES;

    std::array<uint8_t, NONCE_SIZE> nonce;
    randombytes_buf(nonce.data(), nonce.size());

    std::vector<uint8_t> ciphertext(plaintext.size() + TAG_SIZE);
    unsigned long long ciphertext_len = 0;

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.data(), &ciphertext_len,
            plaintext.data(), plaintext.size(),
            nullptr, 0,  // no additional data
            nullptr,     // nsec unused
            nonce.data(),
            sym_key.data()) != 0) {
        return std::nullopt;
    }
    ciphertext.resize(ciphertext_len);

    // 4. Sign: ML-DSA(kem_ct || nonce || ciphertext)
    std::vector<uint8_t> to_sign;
    to_sign.reserve(encaps->ciphertext.size() + nonce.size() + ciphertext.size());
    to_sign.insert(to_sign.end(), encaps->ciphertext.begin(), encaps->ciphertext.end());
    to_sign.insert(to_sign.end(), nonce.begin(), nonce.end());
    to_sign.insert(to_sign.end(), ciphertext.begin(), ciphertext.end());

    auto sig = mldsa65_sign(to_sign, sender_dsa_sk);
    if (!sig) return std::nullopt;

    // 5. Assemble output: kem_ct || nonce || ciphertext || signature || sender_dsa_pk
    std::vector<uint8_t> output;
    output.reserve(encaps->ciphertext.size() + nonce.size() + ciphertext.size() +
                   sig->size() + sender_dsa_pk.size());
    output.insert(output.end(), encaps->ciphertext.begin(), encaps->ciphertext.end());
    output.insert(output.end(), nonce.begin(), nonce.end());
    output.insert(output.end(), ciphertext.begin(), ciphertext.end());
    output.insert(output.end(), sig->begin(), sig->end());
    output.insert(output.end(), sender_dsa_pk.begin(), sender_dsa_pk.end());

    // Zero sensitive data
    sodium_memzero(sym_key.data(), sym_key.size());

    return output;
}

std::optional<std::vector<uint8_t>> pars_decrypt(
    std::span<const uint8_t> encrypted,
    std::span<const uint8_t> recipient_kem_sk,
    std::span<const uint8_t> sender_dsa_pk) {

    constexpr size_t NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    constexpr size_t TAG_SIZE = crypto_aead_xchacha20poly1305_ietf_ABYTES;
    constexpr size_t MIN_SIZE = MLKEM768_CIPHERTEXT_SIZE + NONCE_SIZE + TAG_SIZE +
                                MLDSA65_SIGNATURE_SIZE + MLDSA65_PUBLIC_KEY_SIZE;

    if (encrypted.size() < MIN_SIZE) {
        return std::nullopt;
    }

    // Parse components
    size_t offset = 0;
    auto kem_ct = encrypted.subspan(offset, MLKEM768_CIPHERTEXT_SIZE);
    offset += MLKEM768_CIPHERTEXT_SIZE;

    auto nonce = encrypted.subspan(offset, NONCE_SIZE);
    offset += NONCE_SIZE;

    size_t ciphertext_len = encrypted.size() - MIN_SIZE + TAG_SIZE;
    auto ciphertext = encrypted.subspan(offset, ciphertext_len);
    offset += ciphertext_len;

    auto signature = encrypted.subspan(offset, MLDSA65_SIGNATURE_SIZE);
    offset += MLDSA65_SIGNATURE_SIZE;

    auto included_sender_pk = encrypted.subspan(offset, MLDSA65_PUBLIC_KEY_SIZE);

    // Verify sender public key matches
    if (!std::equal(sender_dsa_pk.begin(), sender_dsa_pk.end(), included_sender_pk.begin())) {
        return std::nullopt;
    }

    // 1. Verify signature
    std::vector<uint8_t> to_verify;
    to_verify.insert(to_verify.end(), kem_ct.begin(), kem_ct.end());
    to_verify.insert(to_verify.end(), nonce.begin(), nonce.end());
    to_verify.insert(to_verify.end(), ciphertext.begin(), ciphertext.end());

    if (!mldsa65_verify(to_verify, signature, sender_dsa_pk)) {
        return std::nullopt;
    }

    // 2. ML-KEM decapsulate
    auto shared = mlkem768_decapsulate(kem_ct, recipient_kem_sk);
    if (!shared) return std::nullopt;

    // 3. Derive symmetric key
    std::array<uint8_t, 32> sym_key;
    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, nullptr, 0, sym_key.size());
    crypto_generichash_blake2b_update(&state, shared->data(), shared->size());
    crypto_generichash_blake2b_update(&state, sender_dsa_pk.data(), sender_dsa_pk.size());
    // Note: We need recipient's KEM public key here, derive from secret key
    // For now, use a placeholder approach
    crypto_generichash_blake2b_update(&state, recipient_kem_sk.data(), 32); // First 32 bytes as placeholder
    crypto_generichash_blake2b_final(&state, sym_key.data(), sym_key.size());

    // 4. Decrypt with XChaCha20-Poly1305
    std::vector<uint8_t> plaintext(ciphertext.size() - TAG_SIZE);
    unsigned long long plaintext_len = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,  // nsec unused
            ciphertext.data(), ciphertext.size(),
            nullptr, 0,  // no additional data
            nonce.data(),
            sym_key.data()) != 0) {
        sodium_memzero(sym_key.data(), sym_key.size());
        return std::nullopt;
    }
    plaintext.resize(plaintext_len);

    // Zero sensitive data
    sodium_memzero(sym_key.data(), sym_key.size());

    return plaintext;
}

// =============================================================================
// Utility Functions
// =============================================================================

void secure_zero(std::span<uint8_t> data) {
    sodium_memzero(data.data(), data.size());
}

}  // namespace session::pq
