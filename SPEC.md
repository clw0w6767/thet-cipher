THET v21 Specification
======================

1. Parameters
-------------
Master key : 32 bytes
Salt       : 16 bytes random per file
Nonce      : 16 bytes random per file
MAC length : 64 bytes each
Block size : 32 bytes
scrypt     : N=2^17, r=8, p=1

2. Domain labels
----------------
LBL_ENC1 = thet:v21:enc1
LBL_ENC2 = thet:v21:enc2
LBL_ENC3 = thet:v21:enc3
LBL_MAC1 = thet:v21:mac1
LBL_MAC2 = thet:v21:mac2
LBL_NON  = thet:v21:nonce
LBL_HKDF = thet:v21:hkdf:

3. AD encoding
--------------
encode_ad(p1, ..., pn) =
    len(p1)[8B BE] || p1 || ... || len(pn)[8B BE] || pn

Each part prefixed with 8-byte big-endian length.

4. Key derivation
-----------------
master  = scrypt(password, salt, N=2^17, r=8, p=1, dklen=32)
prk     = HKDF-Extract(salt, master)
k_lbl   = HKDF-Expand(prk, LBL_HKDF || lbl, 32)
          for lbl in {nonce, enc1, enc2, enc3, mac1, mac2}

5. Stream nonces
----------------
n1 = HMAC-SHA512(k_nonce, LBL_NON || "n1:" || nonce)[0:16]
n2 = HMAC-SHA512(k_nonce, LBL_NON || "n2:" || nonce)[0:16]
n3 = HMAC-SHA512(k_nonce, LBL_NON || "n3:" || nonce)[0:16]

6. Keystream
------------
For byte offset o and length n:

    start_block = o // 32
    skip        = o % 32
    out         = empty

    for block in start_block .. start_block + ceil((n + skip) / 32):
        c  = block.to_bytes(8, "big")
        s1 = HMAC-SHA256(k_enc1, LBL_ENC1 || n1 || c)
        s2 = HMAC-SHA3-256(k_enc2, LBL_ENC2 || n2 || c)
        s3 = BLAKE2b(k_enc3, LBL_ENC3 || n3 || c)[0:32]
        out ||= s1 XOR s2 XOR s3

    keystream = out[skip .. skip + n]

Keystream is byte-positional: independent of chunk size.

7. Encryption
-------------
salt  = random(16)
nonce = random(16)
ad    = encode_ad(LBL_MAC1, LBL_MAC2, salt, nonce)

mac1 = HMAC-SHA512(k_mac1, ad || ciphertext)
mac2 = BLAKE2b-MAC(k_mac2, ad || ciphertext)

output = salt || nonce || ciphertext || mac1 || mac2

8. Decryption
-------------
Phase 1: stream ciphertext, verify mac1 and mac2 in constant time.
         On mismatch, abort. No output produced.
Phase 2: fstat input. If inode/size/mtime/ctime changed, abort.
Phase 3: stream ciphertext, XOR with keystream, write to temp file.
         fstat again. If changed, abort and delete temp.
         Otherwise atomic renameat2(RENAME_NOREPLACE) to target.

9. File format
--------------
offset 0    : salt(16)
offset 16   : nonce(16)
offset 32   : ciphertext(N)
offset 32+N : mac1(64)
offset 96+N : mac2(64)

Total overhead: 160 bytes.

10. Security claims
-------------------
Claim 1: If at least one of HMAC-SHA256, HMAC-SHA3-256, BLAKE2b is a PRF,
         the keystream is indistinguishable from random.
Claim 2: If at least one of HMAC-SHA512, BLAKE2b-MAC is a secure MAC, the
         ciphertext is unforgeable.
Claim 3: All seven subkeys are computationally independent, given
         HKDF-SHA512 is a PRF.

These claims are informal. No formal proof exists.

11. Non-claims
--------------
THET v21 does NOT claim:
- Post-quantum security
- Side-channel resistance
- Security against kernel-level attackers
- Security on network filesystems
- Security if RNG is broken
- Security if password is weak

12. References
--------------
RFC 5869 (HKDF)
RFC 7914 (scrypt)
RFC 7693 (BLAKE2)
NIST FIPS 180-4 (SHA-2)
NIST FIPS 202 (SHA-3)
OWASP Password Storage Cheat Sheet
