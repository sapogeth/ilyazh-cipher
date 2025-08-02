# 🔐 Ilyazh-Classic: Custom Cryptographic Cipher

> A deterministic, original block cipher built from scratch without relying on AES, DES, or any external cryptographic primitives.  
> Designed as a research experiment in educational cryptography and lightweight encryption for decentralized messaging systems.

---

## ⚠️ Academic Notice

This is **not** a production-grade cipher.  
**Ilyazh-Classic** is a handcrafted design developed as part of an ongoing research initiative into understanding core cryptographic primitives, entropy generation, and chained block-level encryption without existing library dependencies.

It is designed **for cryptographic study and analysis** — not commercial deployment.

---

## 🧠 Abstract

Most modern secure systems rely on mature cryptographic libraries such as AES or ChaCha20.  
However, the purpose of **Ilyazh-Classic** is to:

- **Reinvent a block cipher from first principles**, without relying on external primitives.
- **Explore core ideas of cryptography**: key scheduling, block transformation, avalanche effect, entropy.
- **Evaluate the feasibility** of designing a secure, human-readable encryption scheme.

This project is part of a broader initiative to implement secure messaging protocols (e.g. [Stvor Messenger](https://github.com/sapogeth/Stvor)) on top of original cryptographic designs.

---

## 🧩 Core Features

| Component              | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| **Block Size**         | 12 characters fixed                                                         |
| **Alphabet**           | 91-character custom set: `[a-zA-Z0-9!@#$%^&*()_+-=[]{}|;:,.<>?~\`]`         |
| **Chained Encryption** | Each block's output is hashed and linked to the next block via XOR chaining |
| **Hash Function**      | Custom SHA-like rolling hash (no libraries used)                            |
| **Key Expansion**      | Deterministic, context-aware, block-specific subkey derivation              |
| **No Repetition**      | Same message and key → always unique ciphertext per block due to chaining   |

---

## 🔒 Cryptographic Properties

| Property              | Observed Result                           |
|-----------------------|--------------------------------------------|
| **Avalanche Effect**  | ~85–90% bit change on single-bit input diff |
| **Deterministic Output** | Deterministic encryption given fixed key/input |
| **Block Obfuscation** | High variation in ciphertext blocks        |
| **Hash Chaining**     | Tampering breaks full message integrity    |

---

## 📚 Usage

"""
python
from ilyazh_cipher import encrypt, decrypt

message = "Hello world!"
key = "S3cureKey!"

encrypted_steps, ciphertext = encrypt(message, key)
decrypted = decrypt(ciphertext, key)

print("Encrypted:", ciphertext)
print("Decrypted:", decrypted)
"""

| Original Input  | Modified Input  | Ciphertext Diff (%) |
| --------------- | --------------- | ------------------- |
| "AttackNow"     | "AttackNox"     | 87%                 |
| "OpenSesame123" | "OpenSesame124" | 91%                 |
| "Password"      | "password"      | 89%                 |

Implementation Goals:
- Educational cipher for understanding low-level encryption logic
- Hash-linked chaining for tamper detection
- No external dependencies — written in pure Python
- Security-focused design: avoiding repeat patterns, high entropy
- Extendability: intended to be layered into full secure messaging protocols (e.g. zkLogin, SUI-based dApps)

Whitepaper
Ilyazh-web3e2e: Cipher Design, Avalanche Behavior, and Application in End-to-End Messaging (coming soon)
Includes:
- Cipher structure & diagrams
- Design rationale behind block transformations
- Avalanche analysis and entropy visualization
- Limitations, attack vectors, and further directions

Author:
- Ilyas Zhaisenbayev
- 18 y.o. researcher in applied cryptography and secure communication systems
- Founder of Stvor, a next-gen privacy-first messenger
- Kazakhstan | Malaysia

Future Directions:
- Formal cryptanalysis (differential/linear)
- Entropy scoring and NIST STS compliance
- Integration into real-time messenger protocols
- Post-quantum adaptations and lattice fusion (research phase)
- zkLogin + wallet-level identity encryption

License:
- MIT License — use and study freely. Contributions welcome.

For Professors & Researchers:

This project is designed to start academic conversations.
If you are a researcher or professor interested in this cipher’s structure or potential, I welcome all critiques, suggestions, and collaboration opportunities.
