# Cryptography MITM & Nonce Reuse: Attacks and Preventions

This repository contains a comprehensive educational project demonstrating critical vulnerabilities in asymmetric cryptographic protocols and their modern mitigations. The project features interactive GUI visualizers for **Diffie-Hellman Man-in-the-Middle (MITM) attacks** and **ElGamal Nonce Reuse (Reuse-k) attacks**.

## 🚀 Overview

Modern cryptography relies on hard mathematical problems, but implementation flaws or unauthenticated channels can render these systems useless. This project explores:
1.  **Diffie-Hellman MITM**: How an active interloper can hijack an unauthenticated key exchange.
2.  **ElGamal Nonce Reuse**: How reusing a single "random" value $k$ can lead to the total recovery of a private key.

## 🛠️ Key Features

### 1. Diffie-Hellman MITM Visualizer (`dh_mitm.py`)
*   **Attack Simulation**: Demonstrates Nischay (the attacker) intercepting public keys from Alice and Bob.
*   **Prevention Methods**:
    *   **ElGamal Digital Signatures**: Authenticating the exchange via long-term keys.
    *   **SHA-256 Binding**: Ensuring integrity through commitment hashes.
    *   **HMAC Authentication**: Using a Pre-Shared Key (PSK) for secure parameter transmission.
*   **Performance Analysis**: Built-in benchmarking for different bit-sizes (256, 512, 768).

### 2. Reuse-k Attack & Prevention (`reuse_k1.py`)
*   **Attack Simulation**: Recovers the private key $x$ by exploiting the reuse of the nonce $k$ in two different signatures.
*   **Mathematical Recovery**: Implements the algebraic derivation of $k$ and $x$ from signature pairs.
*   **Modern Mitigations**:
    *   **SHA-k**: Deterministic $k$ generation using SHA-256 hashing of $(x, m)$.
    *   **HMAC-k (RFC 6979)**: Secure deterministic $k$ generation to prevent misuse.
*   **Dashboard**: Real-time graphs showing attack success rates vs. prevention efficiency.

## 📐 Mathematical Background

### Diffie-Hellman Active Attack
If Alice sends $A = g^a \pmod p$, an attacker intercepts $A$ and sends $E = g^e \pmod p$ to Bob. Bob computes $K = E^b \pmod p$, which the attacker can also compute as $K = B^e \pmod p$.

### ElGamal Private Key Recovery
When $k$ is reused for messages $m_1$ and $m_2$:
1.  $s_1 - s_2 \equiv k^{-1}(m_1 - m_2) \pmod{p-1}$
2.  $k \equiv (m_1 - m_2)(s_1 - s_2)^{-1} \pmod{p-1}$
3.  $x \equiv (m_1 - s_1 k)r^{-1} \pmod{p-1}$

## 💻 Tech Stack
*   **Language**: Python 3.x
*   **GUI**: Tkinter
*   **Math/Crypto**: `hashlib`, `hmac`, `math`, `random`
*   **Visualization**: `matplotlib`

## ⚙️ Installation & Usage

### Prerequisites
Ensure you have Python installed along with the required libraries:
```bash
pip install matplotlib
```

### Running the Visualizers
To start the Diffie-Hellman MITM simulation:
```bash
python dh_mitm.py
```

To start the Nonce Reuse simulation:
```bash
python reuse_k1.py
```

## 📊 Visualizations
The project includes a dynamic dashboard using `matplotlib` to display:
*   **Attack Success Rates**: Visualizing how prevention blocks 100% of attacks.
*   **Latency Metrics**: Performance comparison between different key sizes and hashing methods.
*   **Security Properties**: Analysis of Confidentiality, Integrity, and Authentication (CIA).

## 🛡️ License & Ethics
This project is for **educational purposes only**. It was developed as part of an MSc research project. 
*   **Author**: Sanjeet S. Giri
*   **Legal**: The project respects the principles of the UK Data Protection Act and GDPR regarding responsible handling of cryptographic research.

---
*Developed for the Cryptography Course - Winter Semester 2026*
