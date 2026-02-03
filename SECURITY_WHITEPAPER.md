# Password Manager Security Whitepaper

**Version:** 1.0
**Date:** February 2026
**Classification:** Public

---

## Executive Summary

This document describes the cryptographic architecture and security model of the Password Manager application. The system implements end-to-end encryption where all sensitive data is encrypted on the client device before transmission to the server. The server never has access to plaintext secrets or the cryptographic keys needed to decrypt them.

**Key security properties:**
- Zero-knowledge architecture: server cannot decrypt user secrets
- End-to-end encryption using modern, audited cryptographic primitives
- Multi-device support with secure key distribution
- Key transparency with cryptographic proofs
- Passwordless authentication via OAuth 2.0/OIDC

---

## Table of Contents

1. [Threat Model](#1-threat-model)
2. [Cryptographic Primitives](#2-cryptographic-primitives)
3. [Key Hierarchy](#3-key-hierarchy)
4. [Secret Encryption](#4-secret-encryption)
5. [Device Enrollment](#5-device-enrollment)
6. [Recovery Mechanism](#6-recovery-mechanism)
7. [Key Transparency](#7-key-transparency)
8. [Security Guarantees](#8-security-guarantees)
9. [Limitations and Recommendations](#9-limitations-and-recommendations)

---

## 1. Threat Model

### 1.1 Trust Assumptions

| Entity | Trust Level | Justification |
|--------|-------------|---------------|
| Client Device | Trusted | User's device with secure storage |
| Operating System | Trusted | Provides secure key storage APIs |
| Server | Semi-trusted | Stores encrypted data; cannot decrypt |
| Network | Untrusted | TLS provides transport security |
| Identity Provider | Trusted | Zitadel manages authentication |

### 1.2 Adversary Capabilities

We defend against adversaries who can:

- **Compromise the server database**: Encrypted blobs are useless without client keys
- **Intercept network traffic**: TLS 1.3+ encrypts all communications
- **Steal a single device**: Device-specific encryption keys limit blast radius
- **Attempt brute force attacks**: 256-bit keys provide sufficient entropy

### 1.3 Out of Scope

The following threats are outside our security model:

- Compromised client device with root/admin access
- Malicious client application (supply chain attacks)
- Side-channel attacks on client cryptographic operations
- Quantum computing attacks (future consideration)

---

## 2. Cryptographic Primitives

All cryptographic operations use well-audited, industry-standard algorithms implemented by the `aes-gcm`, `x25519-dalek`, `ed25519-dalek`, and `argon2` Rust crates.

### 2.1 Algorithm Summary

| Purpose | Algorithm | Key Size | Security Level |
|---------|-----------|----------|----------------|
| Symmetric Encryption | AES-256-GCM | 256-bit | 256-bit |
| Key Exchange | X25519 (ECDH) | 256-bit | 128-bit |
| Digital Signatures | Ed25519 | 256-bit | 128-bit |
| Key Derivation | Argon2id | 256-bit output | Memory-hard |
| Hashing | SHA-256 | 256-bit output | 128-bit collision |
| Random Generation | OS CSPRNG | N/A | System entropy |

### 2.2 AES-256-GCM

All symmetric encryption uses AES-256 in Galois/Counter Mode (GCM), providing:
- **Confidentiality**: 256-bit key encryption
- **Authenticity**: 128-bit authentication tag
- **Integrity**: Tamper detection via AEAD

Ciphertext format:
```
[nonce (12 bytes)] [ciphertext] [authentication tag (16 bytes)]
```

Each encryption operation uses a fresh random 96-bit nonce, ensuring nonce uniqueness across the lifetime of each key.

### 2.3 X25519 Key Exchange

Elliptic Curve Diffie-Hellman over Curve25519 enables:
- Secure key agreement between parties
- Forward secrecy when using ephemeral keys
- 128-bit security against classical computers

### 2.4 Ed25519 Signatures

Edwards-curve Digital Signature Algorithm provides:
- Non-repudiation of key registration
- Certificate authenticity verification
- 128-bit security level

### 2.5 Argon2id Key Derivation

For any password-derived keys, Argon2id is configured with:
- **Memory**: 64 MB
- **Iterations**: 3
- **Parallelism**: 4 threads
- **Output**: 256 bits

These parameters resist GPU-based attacks while remaining practical on mobile devices.

---

## 3. Key Hierarchy

### 3.1 Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    VAULT KEYS (Per User)                    │
│  Created once, distributed to each device                   │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────┐    ┌─────────────────────────────┐│
│  │  Private Keys       │    │  Public Keys (Server)       ││
│  │  (Device-encrypted) │    │  (Publicly accessible)      ││
│  ├─────────────────────┤    ├─────────────────────────────┤│
│  │ • X25519 Secret     │    │ • X25519 Public             ││
│  │   (Key exchange)    │    │   (Receive shared keys)     ││
│  │                     │    │                             ││
│  │ • Ed25519 Secret    │    │ • Ed25519 Public            ││
│  │   (Signing)         │    │   (Verify signatures)       ││
│  └─────────────────────┘    └─────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  Device Keys    │  │  Secret Keys    │  │  Recovery Key   │
│  (Per Device)   │  │  (Per Secret)   │  │  (User-held)    │
├─────────────────┤  ├─────────────────┤  ├─────────────────┤
│ Device          │  │ Content Key     │  │ 256-bit         │
│ Encryption Key  │  │ (AES-256)       │  │ symmetric key   │
│ (DEK)           │  │                 │  │                 │
│                 │  │ Metadata Key    │  │ Encrypts vault  │
│ Encrypts vault  │  │ (AES-256)       │  │ keys for        │
│ private keys    │  │                 │  │ emergency       │
│ on this device  │  │ Encrypted per   │  │ recovery        │
│                 │  │ recipient       │  │                 │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

### 3.2 Device Encryption Key (DEK)

Each device generates a unique 256-bit symmetric key:

- **Storage**: Platform secure storage (iOS Keychain, Android Keystore, Web Crypto)
- **Purpose**: Encrypts vault private keys at rest on that device
- **Scope**: Never leaves the device; not backed up
- **Rotation**: New DEK generated on device enrollment

### 3.3 Vault Keys

Each user has one vault keypair set:

| Key | Type | Size | Purpose |
|-----|------|------|---------|
| Vault Private Key | X25519 | 32 bytes | Decrypt shared secret keys |
| Vault Signing Key | Ed25519 | 32 bytes | Sign audit entries, prove ownership |
| Vault Public Key | X25519 | 32 bytes | Recipients encrypt keys to this |
| Vault Verifying Key | Ed25519 | 32 bytes | Verify user's signatures |

### 3.4 Secret Keys

Each secret has two independent keys:

| Key | Purpose | Benefit |
|-----|---------|---------|
| Content Key | Encrypts secret data (passwords, cards, etc.) | Full content protection |
| Metadata Key | Encrypts name, tags, timestamps | List secrets without decrypting content |

This separation enables the UI to display secret names without decrypting sensitive content.

---

## 4. Secret Encryption

### 4.1 Encryption Flow

When a user creates a secret:

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Secret Content  │     │  Secret Metadata │     │    Secret Keys   │
│  (JSON)          │     │  (JSON)          │     │                  │
└────────┬─────────┘     └────────┬─────────┘     └────────┬─────────┘
         │                        │                        │
         ▼                        ▼                        ▼
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Generate        │     │  Generate        │     │  Encrypt with    │
│  Content Key     │     │  Metadata Key    │     │  recipient's     │
│  (256-bit)       │     │  (256-bit)       │     │  public key      │
└────────┬─────────┘     └────────┬─────────┘     └────────┬─────────┘
         │                        │                        │
         ▼                        ▼                        ▼
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  AES-256-GCM     │     │  AES-256-GCM     │     │  X25519 ECDH +   │
│  Encrypt         │     │  Encrypt         │     │  AES-256-GCM     │
└────────┬─────────┘     └────────┬─────────┘     └────────┬─────────┘
         │                        │                        │
         ▼                        ▼                        ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        SERVER STORAGE                                │
│  encrypted_content | encrypted_metadata | encrypted_keys_per_user   │
└──────────────────────────────────────────────────────────────────────┘
```

### 4.2 Data Structures

**Secret Content** (encrypted):
```json
{
  "type": "login",
  "version": 1,
  "fields": {
    "username": {"type": "text", "label": "Username", "value": "alice"},
    "password": {"type": "password", "label": "Password", "value": "s3cr3t"},
    "url": {"type": "url", "label": "Website", "value": "https://example.com"}
  },
  "custom": {}
}
```

**Secret Metadata** (encrypted separately):
```json
{
  "name": "Example Account",
  "type": "login",
  "tags": ["work"],
  "favorite": false,
  "icon": null,
  "created_at": 1706745600,
  "updated_at": 1706745600
}
```

### 4.3 Key Wrapping for Sharing

When sharing a secret with another user:

1. Fetch recipient's X25519 public key from server
2. Generate ephemeral X25519 keypair
3. Compute shared secret: `ECDH(ephemeral_secret, recipient_public)`
4. Derive wrapping key: `SHA256(shared_secret || "key-sharing-v1")`
5. Encrypt content key and metadata key with wrapping key
6. Send: `{ephemeral_public, encrypted_content_key, encrypted_metadata_key}`

The recipient reverses this process using their vault private key.

---

## 5. Device Enrollment

### 5.1 Overview

New devices are enrolled through an approval flow that securely transfers vault keys from an existing device without exposing them to the server.

### 5.2 Protocol

```
    NEW DEVICE                    SERVER                    EXISTING DEVICE
        │                           │                              │
        │  1. Generate X25519       │                              │
        │     ephemeral keypair     │                              │
        │                           │                              │
        │  2. POST /enrollments     │                              │
        │     {device_public_key}   │                              │
        │  ─────────────────────►   │                              │
        │                           │                              │
        │  3. {enrollment_id}       │                              │
        │  ◄─────────────────────   │                              │
        │                           │                              │
        │  [Display QR code with    │   4. GET /enrollments/pending│
        │   enrollment_id]          │   ◄─────────────────────────  │
        │                           │                              │
        │                           │   5. {enrollment details}     │
        │                           │   ─────────────────────────►  │
        │                           │                              │
        │                           │   6. User approves           │
        │                           │      Existing device:        │
        │                           │      - ECDH with new pubkey  │
        │                           │      - Encrypt vault keys    │
        │                           │                              │
        │                           │   7. POST /enrollments/{id}  │
        │                           │      /approve                │
        │                           │      {encrypted_vault_key}   │
        │                           │   ◄─────────────────────────  │
        │                           │                              │
        │  8. Poll for approval     │                              │
        │  GET /enrollments/{id}    │                              │
        │     /status               │                              │
        │  ─────────────────────►   │                              │
        │                           │                              │
        │  9. {encrypted_vault_key} │                              │
        │  ◄─────────────────────   │                              │
        │                           │                              │
        │  10. Decrypt vault keys   │                              │
        │      using ECDH           │                              │
        │                           │                              │
        │  11. Generate device DEK  │                              │
        │      Re-encrypt for       │                              │
        │      local storage        │                              │
        │                           │                              │
        │  12. POST /enrollments    │                              │
        │      /{id}/complete       │                              │
        │  ─────────────────────►   │                              │
        │                           │                              │
        ▼                           ▼                              ▼
```

### 5.3 Security Properties

- **No plaintext keys on server**: Encrypted blob is opaque to server
- **Ephemeral key exchange**: Fresh keys for each enrollment
- **User approval required**: Prevents unauthorized device additions
- **Time-limited**: Enrollments expire after 5 minutes
- **Device isolation**: Each device has unique DEK

---

## 6. Recovery Mechanism

### 6.1 Recovery Key Generation

When a user first creates their vault:

1. Generate 256-bit random recovery key
2. Display to user in hex format: `XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX`
3. Compute hash: `SHA256("recovery-key-v1" || recovery_key)`
4. Encrypt vault keys with recovery key using AES-256-GCM
5. Store on server: `{recovery_key_hash, encrypted_vault_key}`

### 6.2 Recovery Flow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  User enters    │     │  Fetch from     │     │  Decrypt vault  │
│  recovery key   │────►│  server:        │────►│  keys with      │
│  on new device  │     │  encrypted blob │     │  recovery key   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                                                        ▼
                                               ┌─────────────────┐
                                               │  Generate new   │
                                               │  device DEK,    │
                                               │  re-encrypt     │
                                               └─────────────────┘
```

### 6.3 Security Properties

- **User-controlled**: Recovery key never stored on server
- **One-way hash**: Server cannot derive recovery key from hash
- **Offline recovery**: No server approval needed
- **Single-use recommended**: Generate new recovery key after use

---

## 7. Key Transparency

### 7.1 Purpose

Key transparency prevents the server from:
- Substituting a different public key for a user
- Claiming different keys existed at different times
- Equivocating about key history

### 7.2 Certificate Structure

When a user registers their vault keys:

```json
{
  "principal_id": "user-uuid",
  "public_key": "base64-encoded-x25519-public",
  "public_signing_key": "base64-encoded-ed25519-public",
  "issued_at": "2026-02-01T00:00:00Z",
  "valid_until": "2027-02-01T00:00:00Z",
  "server_signature": "base64-encoded-ed25519-signature"
}
```

The server signs this certificate with its Ed25519 private key.

### 7.3 Merkle Tree

All key registrations are appended to a Merkle tree:

```
                    Root Hash
                   /         \
            Hash(A,B)       Hash(C,D)
           /       \       /       \
      Leaf(A)  Leaf(B)  Leaf(C)  Leaf(D)
         │        │        │        │
      User 1   User 2   User 3   User 4
```

**Leaf hashing**: `SHA256(0x00 || leaf_data)`
**Node hashing**: `SHA256(0x01 || left || right)`

Domain separation (0x00 vs 0x01) prevents second-preimage attacks.

### 7.4 Inclusion Proofs

Clients can verify their key is in the log:

1. Request inclusion proof from server
2. Compute leaf hash from own certificate
3. Combine with sibling hashes along path
4. Verify computed root matches published root

---

## 8. Security Guarantees

### 8.1 Confidentiality

| Data | Protection |
|------|------------|
| Secret content | AES-256-GCM with per-secret key |
| Secret metadata | AES-256-GCM with per-secret key |
| Vault private keys | AES-256-GCM with device DEK |
| Secret keys (shared) | X25519 ECDH + AES-256-GCM |

### 8.2 Integrity

| Data | Protection |
|------|------------|
| Encrypted blobs | GCM authentication tag |
| Certificates | Ed25519 server signature |
| Key history | Merkle tree inclusion proofs |

### 8.3 Authentication

| Action | Mechanism |
|--------|-----------|
| User login | OAuth 2.0 / OIDC (Zitadel) |
| Device enrollment | User approval from existing device |
| Key ownership | Ed25519 signatures on operations |

### 8.4 Non-repudiation

- Server signatures on certificates prove issuance
- User signatures on audit entries prove actions
- Merkle tree provides tamper-evident history

---

## 9. Limitations and Recommendations

### 9.1 Known Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| No forward secrecy for stored secrets | Compromised content key decrypts all versions | Key rotation (future) |
| Recovery key is single point of failure | Lost key = lost vault | Emphasize backup importance |
| Keys held in memory | Vulnerable to memory dumps | Use `zeroize` crate |
| Trust-on-first-use for server key | MITM possible on first connection | Pin server key in app |

### 9.2 Operational Recommendations

1. **Secure deployment**: Run server on hardened infrastructure
2. **Database encryption**: Enable encryption at rest for PostgreSQL
3. **Key backup**: Securely backup server signing key
4. **Monitoring**: Alert on unusual enrollment patterns
5. **Rate limiting**: Prevent brute force on recovery endpoints

### 9.3 User Recommendations

1. **Recovery key storage**: Write down and store in physical safe
2. **Device hygiene**: Keep devices updated and malware-free
3. **Review devices**: Periodically audit enrolled devices
4. **Enable 2FA**: Use strong authentication with identity provider

---

## Appendix A: Cryptographic Parameters

```
AES-256-GCM:
  Key size:     256 bits
  Nonce size:   96 bits
  Tag size:     128 bits

X25519:
  Private key:  256 bits
  Public key:   256 bits
  Shared secret: 256 bits

Ed25519:
  Private key:  256 bits
  Public key:   256 bits
  Signature:    512 bits

Argon2id:
  Memory:       65536 KiB (64 MB)
  Iterations:   3
  Parallelism:  4
  Output:       256 bits

SHA-256:
  Output:       256 bits
```

---

## Appendix B: References

1. **AES-GCM**: NIST SP 800-38D
2. **X25519**: RFC 7748
3. **Ed25519**: RFC 8032
4. **Argon2**: RFC 9106
5. **Merkle Trees**: RFC 6962 (Certificate Transparency)

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | February 2026 | Initial release |

---

*This document is provided for informational purposes. The cryptographic implementation should be reviewed by qualified security professionals before production deployment.*
