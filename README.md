# Cryptography Algorithms

This repository contains a Python script (`Cryptography_Algorithms.py`) demonstrating various fundamental cryptographic algorithms and protocols. It serves as a comprehensive educational resource for understanding the core principles behind modern cryptography.

## Table of Contents

-   [Features](#features)
-   [Algorithms Included](#algorithms-included)
-   [Usage](#usage)
-   [Requirements](#requirements)
-   [Author](#author)
-   [Date](#date)

## Features

* **Educational Purpose**: Clear and concise implementations for learning cryptographic concepts.
* **Variety of Algorithms**: Covers a broad range of symmetric, asymmetric, key exchange, hashing, and digital signature schemes.
* **Practical Examples**: Each algorithm includes example usage to demonstrate its functionality.
* **Well-commented Code**: The code is thoroughly commented to explain the logic and steps involved.

## Algorithms Included

The script implements the following cryptographic algorithms:

### Symmetric Ciphers
* **Caesar Cipher**: A simple substitution cipher.
* **Vigenere Cipher**: A method of encrypting alphabetic text by using a series of different Caesar ciphers based on the letters of a keyword.
* **Vernam Cipher (One-Time Pad)**: An unbreakable encryption scheme if the key is truly random, never reused, and kept secret.

### Asymmetric Ciphers
* **RSA**: A widely used public-key cryptosystem for secure data transmission.
* **ElGamal**: Another public-key cryptosystem based on the Diffie-Hellman key exchange.

### Key Exchange Protocols
* **Diffie-Hellman**: A method of securely exchanging cryptographic keys over a public channel.
* **ECDH (Elliptic Curve Diffie-Hellman)**: An anonymous key agreement protocol that allows two parties, each having an elliptic curve public/private key pair, to establish a shared secret over an insecure channel.

### Hashing Algorithms
* **SHA-256**: Secure Hash Algorithm 256-bit.
* **SHA-512**: Secure Hash Algorithm 512-bit.
* **SHA3-256**: SHA-3 variant producing a 256-bit hash.
* **SHA3-512**: SHA-3 variant producing a 512-bit hash.

### Digital Signatures
* **RSA Digital Signature**: Uses RSA public-key cryptography to verify the authenticity and integrity of a message.
* **ECDSA (Elliptic Curve Digital Signature Algorithm)**: A variant of the Digital Signature Algorithm (DSA) which uses elliptic curve cryptography.

### Cryptanalysis
* **Frequency Analysis**: A method used to break substitution ciphers, demonstrated here for the Caesar cipher.

## Usage

To run the script and see the demonstrations of each algorithm:

1.  **Clone the repository (if applicable) or download the file `Cryptography_Algorithms.py`.**
2.  **Navigate to the directory containing the file in your terminal.**
3.  **Run the script using Python:**
    ```bash
    python Cryptography_Algorithms.py
    ```

The output for each algorithm's encryption/decryption or key exchange process will be printed to the console.

## Requirements

* Python 3.x (tested with Python 3.x)

## Author

* **ALOUACH Abdennour**
    *MIATE (Master of Artificial Intelligence and Emerging Technologies)*

## Date

* 14/07/2025 (Initial creation/last update)
