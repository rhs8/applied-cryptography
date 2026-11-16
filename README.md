This repository explores cryptographic algorithms, vulnerabilities, and cryptanalysis techniques through practical Python implementations.

## Projects

### 1. Vigenère Cipher Cryptanalysis

A Python-based tool for analyzing and decrypting Vigenère ciphers using statistical cryptanalysis.

**Features:**
- Index of Coincidence (IC) for key-length estimation.
- Chi-Squared statistical analysis.
- Frequency-based key recovery.
- Vigenère encryption and decryption.
- Configurable command-line interface.
- Plaintext output and round-trip verification.

**Techniques:** Frequency analysis, modular arithmetic, statistical analysis, and classical cryptanalysis.

### 2. Two-Time Pad

Investigate the security implications of reusing a one-time pad key across multiple plaintexts.

**Objective:** Recover the contents of two encrypted files using crib-dragging and XOR analysis.

### 3. Padding Oracle Attack

Study a vulnerability in AES encryption when CBC mode is combined with an insecure padding-validation mechanism.

**Objective:** Implement a Python program that uses a provided padding oracle to recover plaintext from ciphertext.

## Learning Outcomes

- Understand cryptographic algorithms and common implementation weaknesses.
- Apply mathematical and computational techniques to analyze encrypted data.
- Implement cryptographic analysis algorithms in Python.
- Understand the security implications of key reuse and insecure padding validation.
- Develop reusable command-line tools for cryptographic analysis.
