# THET v21 - An Experimental Symmetric Cipher

**NOT for production use. NOT audited.**

This is a learning project. I'm publishing it to get feedback from the
cryptography community. Do NOT use it to protect real data.

Use XChaCha20-Poly1305 (https://doc.libsodium.org/secret-key_cryptography/secretstream)
or AES-256-GCM (https://en.wikipedia.org/wiki/Galois/Counter_Mode) for anything that matters.

---

## What is this?

THET v21 is a self-designed symmetric cipher I built to learn how
cryptography actually works. It went through ~15 versions (v7 -> v21),
each fixing bugs found by iterative review.

The final design is deliberately boring:

- Three-stream XOR keystream: HMAC-SHA256 XOR HMAC-SHA3-256 XOR BLAKE2b
- HKDF-SHA512 for key separation (7 independent subkeys)
- Dual MAC: HMAC-SHA512 + BLAKE2b-MAC (two independent primitive families)
- scrypt (N=2^17, r=8, p=1) for password derivation
- Random 16-byte nonce (not SIV; no nonce reuse problem)
- Streaming, two-pass decryption with atomic rename
- Rust implementation with hardened I/O

## Why does it exist?

It should not. This is a learning artifact. Real-world encryption should
use audited standards. If you're reading this to evaluate whether to use
it: don't.

## Security design

See SPEC.md for the full specification.

Three-stream keystream:

    s1 = HMAC-SHA256(k_enc1, LBL_ENC1 || n1 || block_ctr)
    s2 = HMAC-SHA3-256(k_enc2, LBL_ENC2 || n2 || block_ctr)
    s3 = BLAKE2b(k_enc3, LBL_ENC3 || n3 || block_ctr)
    keystream_block = s1 XOR s2 XOR s3

Security reduces to: at least one of HMAC-SHA256, HMAC-SHA3-256, BLAKE2b is a PRF.

Dual MAC:

    mac1 = HMAC-SHA512(k_mac1, ad || ciphertext)
    mac2 = BLAKE2b-MAC(k_mac2, ad || ciphertext)

Security reduces to: at least one of HMAC-SHA512, BLAKE2b-MAC is a secure MAC.

## Build

    cargo build --release

Requires Rust 1.70+. Linux only (uses statx, flock, renameat2).

## Usage

    THET_PASSPHRASE="your passphrase" ./target/release/thet21 encrypt secret.txt secret.thet21
    THET_PASSPHRASE="your passphrase" ./target/release/thet21 decrypt secret.thet21 recovered.txt

If THET_PASSPHRASE is not set, the program prompts interactively.

## File format

    offset 0        : salt(16)      - scrypt salt, random per file
    offset 16       : nonce(16)     - keystream nonce, random per file
    offset 32       : ciphertext(N) - plaintext XOR keystream
    offset 32+N     : mac1(64)      - HMAC-SHA512
    offset 96+N     : mac2(64)      - BLAKE2b-MAC

## Known limitations

See SECURITY.md for the full list. Summary:

- No post-quantum security
- No side-channel resistance
- NFS flock not reliable (mitigated with fcntl OFD locks)
- Kernel-level attackers not defended against
- Not audited by anyone

## What I want from you

If you're a cryptographer:

- Break it. Tell me where it fails.
- Critique the design. Is the three-stream XOR meaningful?
- Compare to standards. Where does it fall short of XChaCha20-Poly1305?

If you find a bug, open an issue. If you find a real break, open an issue
and I'll credit you.

## Version history

| Version | Key change |
|---------|------------|
| v7      | Initial (broken) |
| v8-v12  | Iterative fixes (keystream reuse, key handling) |
| v13-v14 | AD encoding, SIV, domain separation |
| v15-v16 | SIV nonce verification, spec docs |
| v17-v18 | Removed temp file plaintext spill, removed redundant SIV |
| v19-v20 | TOCTOU defenses, fstat fingerprints, flock |
| v21     | Rust rewrite, hardened I/O |

## License

MIT. See LICENSE.
