// Pars Network Post-Quantum Cryptography
// NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA)

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace session::pq {

// =============================================================================
// Constants - NIST FIPS 203/204 compliant sizes
// =============================================================================

// ML-KEM-768 (NIST Level 3 - recommended for Pars)
constexpr size_t MLKEM768_PUBLIC_KEY_SIZE = 1184;
constexpr size_t MLKEM768_SECRET_KEY_SIZE = 2400;
constexpr size_t MLKEM768_CIPHERTEXT_SIZE = 1088;
constexpr size_t MLKEM768_SHARED_SECRET_SIZE = 32;

// ML-KEM-1024 (NIST Level 5 - maximum security)
constexpr size_t MLKEM1024_PUBLIC_KEY_SIZE = 1568;
constexpr size_t MLKEM1024_SECRET_KEY_SIZE = 3168;
constexpr size_t MLKEM1024_CIPHERTEXT_SIZE = 1568;
constexpr size_t MLKEM1024_SHARED_SECRET_SIZE = 32;

// ML-DSA-65 (NIST Level 3 - recommended for Pars)
constexpr size_t MLDSA65_PUBLIC_KEY_SIZE = 1952;
constexpr size_t MLDSA65_SECRET_KEY_SIZE = 4032;
constexpr size_t MLDSA65_SIGNATURE_SIZE = 3309;  // liboqs 0.15.0

// ML-DSA-87 (NIST Level 5 - maximum security)
constexpr size_t MLDSA87_PUBLIC_KEY_SIZE = 2592;
constexpr size_t MLDSA87_SECRET_KEY_SIZE = 4896;
constexpr size_t MLDSA87_SIGNATURE_SIZE = 4627;  // liboqs 0.15.0

// Pars Session ID prefix (distinguishes from legacy "05" X25519 IDs)
constexpr std::string_view PARS_SESSION_ID_PREFIX = "07";

// =============================================================================
// Type aliases for clarity
// =============================================================================

using mlkem768_public_key = std::array<uint8_t, MLKEM768_PUBLIC_KEY_SIZE>;
using mlkem768_secret_key = std::array<uint8_t, MLKEM768_SECRET_KEY_SIZE>;
using mlkem768_ciphertext = std::array<uint8_t, MLKEM768_CIPHERTEXT_SIZE>;
using shared_secret = std::array<uint8_t, MLKEM768_SHARED_SECRET_SIZE>;

using mldsa65_public_key = std::array<uint8_t, MLDSA65_PUBLIC_KEY_SIZE>;
using mldsa65_secret_key = std::array<uint8_t, MLDSA65_SECRET_KEY_SIZE>;
using mldsa65_signature = std::array<uint8_t, MLDSA65_SIGNATURE_SIZE>;

// =============================================================================
// Key Generation
// =============================================================================

struct MLKEMKeyPair {
    mlkem768_public_key public_key;
    mlkem768_secret_key secret_key;
};

struct MLDSAKeyPair {
    mldsa65_public_key public_key;
    mldsa65_secret_key secret_key;
};

// Combined PQ identity for Pars network
struct ParsIdentity {
    MLKEMKeyPair kem;      // For key encapsulation (receiving messages)
    MLDSAKeyPair dsa;      // For signatures (sending messages)
    std::string session_id; // "07" + hex(Blake2b(kem.pub || dsa.pub))
};

/// Generate a new ML-KEM-768 keypair
/// @returns keypair or nullopt on failure
std::optional<MLKEMKeyPair> mlkem768_keygen();

/// Generate a new ML-DSA-65 keypair
/// @returns keypair or nullopt on failure
std::optional<MLDSAKeyPair> mldsa65_keygen();

/// Generate a complete Pars identity (KEM + DSA + Session ID)
/// @returns identity or nullopt on failure
std::optional<ParsIdentity> generate_pars_identity();

/// Derive Pars Session ID from public keys
/// Format: "07" + hex(Blake2b-256(kem_pk || dsa_pk))
/// @param kem_pk ML-KEM public key
/// @param dsa_pk ML-DSA public key
/// @returns 66-character session ID string
std::string derive_session_id(
    std::span<const uint8_t> kem_pk,
    std::span<const uint8_t> dsa_pk);

// =============================================================================
// ML-KEM Key Encapsulation (replaces X25519)
// =============================================================================

struct EncapsulationResult {
    mlkem768_ciphertext ciphertext;  // Send to recipient
    shared_secret secret;             // Use for symmetric encryption
};

/// Encapsulate a shared secret for a recipient
/// @param recipient_pk Recipient's ML-KEM public key
/// @returns ciphertext and shared secret, or nullopt on failure
std::optional<EncapsulationResult> mlkem768_encapsulate(
    std::span<const uint8_t> recipient_pk);

/// Decapsulate a shared secret from ciphertext
/// @param ciphertext The encapsulated ciphertext
/// @param secret_key Recipient's ML-KEM secret key
/// @returns shared secret or nullopt on failure
std::optional<shared_secret> mlkem768_decapsulate(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> secret_key);

// =============================================================================
// ML-DSA Signatures (replaces Ed25519)
// =============================================================================

/// Sign a message with ML-DSA-65
/// @param message The message to sign
/// @param secret_key Signer's secret key
/// @returns signature or nullopt on failure
std::optional<mldsa65_signature> mldsa65_sign(
    std::span<const uint8_t> message,
    std::span<const uint8_t> secret_key);

/// Verify an ML-DSA-65 signature
/// @param message The signed message
/// @param signature The signature to verify
/// @param public_key Signer's public key
/// @returns true if valid, false otherwise
bool mldsa65_verify(
    std::span<const uint8_t> message,
    std::span<const uint8_t> signature,
    std::span<const uint8_t> public_key);

// =============================================================================
// Pars E2E Encryption Protocol
// =============================================================================

/// Encrypt a message for a Pars recipient (E2E PQ)
/// Protocol:
///   1. ML-KEM encapsulate to get shared secret
///   2. Derive symmetric key: K = Blake2b(shared || sender_dsa_pk || recipient_kem_pk)
///   3. Encrypt: XChaCha20-Poly1305(message, K, random_nonce)
///   4. Sign: ML-DSA(kem_ct || nonce || ciphertext)
///
/// @param plaintext Message to encrypt
/// @param sender_dsa_sk Sender's ML-DSA secret key (for signing)
/// @param sender_dsa_pk Sender's ML-DSA public key (included in message)
/// @param recipient_kem_pk Recipient's ML-KEM public key
/// @returns encrypted message blob or nullopt on failure
std::optional<std::vector<uint8_t>> pars_encrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> sender_dsa_sk,
    std::span<const uint8_t> sender_dsa_pk,
    std::span<const uint8_t> recipient_kem_pk);

/// Decrypt a Pars E2E message
/// @param ciphertext Encrypted message blob
/// @param recipient_kem_sk Recipient's ML-KEM secret key
/// @param sender_dsa_pk Sender's ML-DSA public key (for verification)
/// @returns plaintext or nullopt on failure/invalid signature
std::optional<std::vector<uint8_t>> pars_decrypt(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> recipient_kem_sk,
    std::span<const uint8_t> sender_dsa_pk);

// =============================================================================
// Hybrid Mode (for TLS 1.3 compatibility only - NOT for E2E)
// =============================================================================

/// Hybrid key exchange combining X25519 + ML-KEM
/// ONLY for external TLS connections, NOT for Pars E2E messaging
/// E2E must be pure PQ
struct HybridKeyExchange {
    std::array<uint8_t, 32> x25519_public;
    mlkem768_public_key mlkem_public;
};

struct HybridSharedSecret {
    std::array<uint8_t, 32> combined;  // HKDF(x25519_ss || mlkem_ss)
};

/// WARNING: This is ONLY for TLS 1.3 external connections
/// Pars E2E messaging MUST use pure PQ (pars_encrypt/pars_decrypt)
std::optional<HybridSharedSecret> hybrid_key_exchange(
    std::span<const uint8_t> peer_x25519_pk,
    std::span<const uint8_t> peer_mlkem_pk,
    std::span<const uint8_t> our_x25519_sk,
    std::span<const uint8_t> our_mlkem_sk);

// =============================================================================
// Utility Functions
// =============================================================================

/// Check if a session ID is a Pars PQ ID (starts with "07")
inline bool is_pars_session_id(std::string_view session_id) {
    return session_id.size() == 66 && session_id.starts_with(PARS_SESSION_ID_PREFIX);
}

/// Check if a session ID is a legacy X25519 ID (starts with "05")
inline bool is_legacy_session_id(std::string_view session_id) {
    return session_id.size() == 66 && session_id.starts_with("05");
}

/// Secure memory zeroing
void secure_zero(std::span<uint8_t> data);

/// Initialize the PQ crypto library (call once at startup)
/// @returns true on success
bool init();

}  // namespace session::pq
