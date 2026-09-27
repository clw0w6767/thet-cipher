# Security Policy

## Status

NOT audited. NOT for production use.

This is an experimental cipher. It has been publicly available since 2026
and has not received cryptanalysis from any third party.

## Reporting a Vulnerability

Open a GitHub issue. If the vulnerability is sensitive, use GitHub's
private security advisory feature.

Please include:

- A clear description of the attack
- Steps to reproduce (if applicable)
- Impact assessment
- Any proof-of-concept code

## Known Limitations

THET v21 does NOT provide:

### Cryptographic

- Post-quantum security.
- Security proofs. The three-stream XOR and dual MAC reductions are informal.
- Side-channel resistance. Timing, cache, power analysis not addressed.

### Operational

- Kernel-level attackers. Root can read memory and observe everything.
- Cold-boot attacks. RAM contents can be recovered.
- Hardware implants. Out of scope.
- NFS / SMB. File locking not reliable on all network filesystems.
- mmap writes. The implementation scans /proc/*/maps to detect memory-mapped
  files, but there is a TOCTOU window. mmap writes bypass flock by design.
- Fork safety.

### Design

- Determinism. With same salt, nonce, plaintext, ciphertext is identical.
- No forward secrecy.
- No key commitment.

## Threat Model

In scope:

- Passive network attacker
- Storage compromise (attacker gets the ciphertext file)
- Offline brute-force (mitigated by scrypt)
- Ciphertext tampering (mitigated by dual MAC)

Out of scope:

- Root-level attacker
- Physical access to running machine
- Coercion / rubber-hose cryptanalysis
- Quantum adversary
- Side-channel attacker with local access

## Contact

Open a GitHub issue.
