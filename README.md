# Breaking Cryptography

This project explores cryptographic vulnerabilities through practical implementations and cryptanalysis techniques.

## Overview

### 1. Two-Time Pad

Investigate the security implications of reusing a one-time pad key across multiple plaintexts.

**Objective:** Recover the contents of two encrypted files (`ctext0` and `ctext1`) using crib-dragging and XOR analysis.

### 2. Padding Oracle Attack

Study a vulnerability in AES encryption when CBC mode is combined with an insecure padding-validation mechanism.

**Objective:** Implement a Python program (`decrypt.py`) that uses the provided course padding oracle to recover plaintext from ciphertext.


## Learning Outcomes

- Understand common weaknesses in cryptographic implementations.
- Apply mathematical and computational techniques to analyze encrypted data.
- Implement cryptographic analysis algorithms in Python.
- Understand how key reuse and insecure padding validation can compromise confidentiality.
