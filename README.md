# AC_GROUP6_Final-Project

### CSAC 329 - Applied Cryptography | Cryptographic Application
**Date:** May 24, 2025

## 👥 Group Members

- De Silva, Mark Bryan 
- Parañal, Mary Rachel
- Valle, Nerisa

---

## 📖 Introduction

This project is a simple application developed for the Applied Cryptography (CSAC 329) course. Its purpose is to implement various cryptographic techniques to secure communication, data, and information exchange. Cryptography plays a critical role in protecting the confidentiality, integrity, and authenticity of messages and files. The application provides a user-friendly interface that allows users to encrypt, decrypt, and hash both text and files using different cryptographic algorithms.

---

## 🎯 Project Objectives

1. To implement multiple cryptographic algorithms—including symmetric, asymmetric, and hashing methods—for securing both text and file data.
2. To design and develop a user-friendly graphical interface that simplifies the process of performing encryption, decryption, and hashing operations.
3. To demonstrate secure handling of sensitive input and output data within a web environment using modern Python libraries and best practices.
4. To enhance understanding of cryptographic principles through interactive examples, real-time processing, and accessible algorithm explanations.

---

## 🔍 Discussions

### Application Architecture and UI Choice

This cryptographic application is developed using **Flask**, a lightweight and flexible Python web framework. Flask was chosen for its simplicity and efficiency in creating interactive, web-based user interfaces.

The architecture follows a client-server model:

- Frontend: HTML/CSS templates rendered via Flask’s render_template functionality, enabling users to input text, upload files, and choose cryptographic operations through an intuitive web interface.
- Backend: Python handles the core logic for encryption, decryption, and hashing using manually implemented logic and selected cryptographic libraries.
- Integration: Each cryptographic function is mapped to a route in Flask, processing user input and displaying results dynamically.

The UI guides users through selecting an algorithm, entering or uploading data, and viewing results, with descriptions of each algorithm available within the application to promote learning and understanding.

---

### Implemented Cryptographic Algorithms

#### 1. Caesar Cipher
- **Type:** Symmetric
- **History/Background:** Caesar Cipher is one of the earliest known encryption techniques, named after Julius Caesar, who used it to protect military communications. It is a simple substitution cipher that shifts each letter in the plaintext by a fixed number of positions in the alphabet. 
- **Process:** With a given shift (e.g., 3), each letter is replaced by another letter that is three positions ahead in the alphabet (A → D, B → E, etc.). The same shift value is used for both encryption and decryption. 
- **Library:** Custom Python code
- **Integration:** This classic cipher shifts letters by a certain number. Users enter the text and shift values, and the app processes it directly using simple logic for both text and file input.

#### 2. Block Cipher - XOR
- **Type:** Symmetric
- **History/Background:** XOR (exclusive OR) encryption is a basic and fast method for combining plaintext with a repeating key at the binary level. While it is not secure on its own, it is often used in stream ciphers and helps illustrate how binary operations can be used in cryptography.
- **Process:** Each character from the plaintext is XORed with a character from the repeating key. The result is a hexadecimal representation of the XOR values. The same key and operation are used to decrypt.
- **Library:** No external cryptographic libraries are used; implemented using built-in Python functions
- **Integration:** The app allows users to input text and a key, performing XOR encryption/decryption directly. File upload for XOR is also supported and returns a detailed binary/hex breakdown.

#### 3. Vigenère Cipher
- **Type:** Symmetric
- **History/Background:** Vigenère Cipher was first introduced by Giovan Battista Bellaso in 1553, but later popularized and named after Blaise de Vigenère in 1586. Though once believed unbreakable, it was eventually deciphered by Charles Babbage and Friedrich Kasiski using mathematical analysis.
- **Process:** Encrypts text by shifting each letter based on a repeating keyword (a series of Caesar ciphers).
- **Library:** Custom Python code
- **Integration:** Uses a keyword to shift letters in the message. The app lets users input a message and a keyword to encrypt or decrypt text or uploaded files.

#### 4. RSA
- **Type:** Asymmetric
- **History/Background:** RSA was developed in 1977 by Ron Rivest, Adi Shamir, and Leonard Adleman at Massachusetts Institute of Technology. It was designed to secure digital communication over untrusted networks. RSA solved the problem of key distribution in traditional cryptography by introducing public-key encryption.
- **Process:** Encrypts data using the recipient’s public key and decrypts it with their private key, enabling secure communication without prior key exchange.
- **Library:** Custom Python code (using `random` and math functions)
- **Integration:** The app creates RSA key pairs and allows users to encrypt messages with the public key and decrypt them with the private key. Everything is handled inside the app with basic math.

#### 5. Diffie-Hellman
- **Type:** Asymmetric (Key Exchange) 
- **History/Background:** Diffie-Hellman was introduced in 1976 by Whitfield Diffie and Martin Hellman, it was the first widely used method to securely exchange cryptographic keys over a public channel. It laid the foundation for public-key cryptography. 
- **Process:** Two parties agree on a large prime number and a base. Each party chooses a secret number, computes a public value, and exchanges it. Using the received value and their own secret, both compute the same shared secret key. 
- **Library:** `cryptography.hazmat.primitives.asymmetric.dh`, `cryptocode`
- **Integration:** This method securely creates a shared secret between two parties. The shared secret can then be used to encrypt and decrypt messages using the cryptocode library.

#### 6. Hashing Functions (SHA-256, SHA-512, MD5, SHA-1)
- **Type:** Hash 
- **History/Background:** Hash functions were developed to ensure data integrity and security. MD5 was released in 1992, SHA-1 in 1995, and SHA-2 (which includes SHA-256 and SHA-512) in 2001 by the U.S. National Security Agency (NSA). 
- **Process:** Converts input data into a fixed-length hash value. Any change in the input produces a completely different hash. The process is deterministic, fast, and irreversible.
- **Library:** `cryptography.hazmat.primitives.hashes`, `hashlib`
- **Integration:** Converts text or file content into a unique hash value. The app supports different algorithms and shows the result instantly.

---

## 🖥️ Sample Runs/Outputs

Below are text-based output examples for each algorithm's functionality.

### Symmetric Encryption/Decryption

#### Caesar Cipher
**Input Text:**  
`CRYPTOGRAPHY`  
**Key (Shift):** `3`  

**Encrypted Output:**
```
FUBSWRJUDSKB
```
**Decrypted Output:**
```
CRYPTOGRAPHY
```

#### Block Cipher - XOR
**Input Text:**  
`Hello, World!`  
**Key:** `mysecretkey123`  

**Encrypted Output:**
```
25 1C 1F 09 0C 5E 45 23 04 17 15 55 13
```
**Decrypted Output:**
```
Hello, World!
```

#### Vigenère Cipher
**Input Text:**  
`CRYPTOGRAPHY`  
**Key:** `KEY`  
**Alphabet (unique characters):** `ABCDEFGHIJKLMNOPQRSTUVWXYZ`

**Encrypted Output:**
```
MVWZXMQVYZLW
```
**Decrypted Output:**
```
CRYPTOGRAPHY
```

---

### Asymmetric Encryption/Decryption

#### RSA

**Input Text:**  
`Cryptography`  
**Public Key:**  
`-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----` 
**Private Key:**  
`-----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----`

**Encrypted Output:**
```
[29647,4083,44086,6480,20454,46450,20258,4083,19195,6480,7329,44086]
```
**Decrypted Output:**
```
Cryptography
```
--- 

#### Diffie-Hellman

**Input Text:** 
`Confidential`
**Prime (p):**
`6.74095192508171e+153`
**Generator:** 
`2`

**Alice**
**Private Key (a):**
`5.40282997502746e+153`
**Public Key (A = g^a mod p):**
`3.0208394115311393e+153`
**Shared Secret Key (s = B^a mod p):**
`1.325189689279844e+153`

**Bob**
**Private Key (b):**
`6.283412939142339e+153`
**Public Key (B = g^b mod p):**
`4.273626547162744e+152`
**Shared Secret Key (s = A^b mod p):**
`1.325189689279844e+153`

**Encrypted Output:**
```
[67, 111, 110, 102, 105, 100, 101, 110, 116, 105, 97, 108]
```
**Decrypted Output:**
```
Confidential
```
---

### Hashing Functions

#### SHA-256 (Text)
**Input Text:**  
`sampletext`  
**Output:**
```
a5871e22ae2dc0dcffdaebcffa9d12ab2278e22feaa5cbe2891eba56d52678f5
```

#### MD5 (Text)
**Input Text:**  
`hashme`  
**Output:**
```
533f6357e0210e67d91f651bc49e1278
```
--- 

## 📚 References

- [Wikipedia – XOR cipher](https://en.wikipedia.org/wiki/XOR_cipher) 
- [GeeksforGeeks – Caesar Cipher in Cryptography](https://www.geeksforgeeks.org/caesar-cipher-in-cryptography/)
- [Study.com – Vigenre Cipher History, Example & Coding Variants](https://study.com/academy/lesson/vigenere-cipher-square-decoder.html)
- [Splunk Blogs – RSA Algorithm in Cryptography: Rivest Shamir Adleman Explained](https://www.splunk.com/en_us/blog/learn/rsa-algorithm-cryptography.html)
- [1Kosmos – Diffie-Hellman Key Exchange Algorithm](https://www.1kosmos.com/security-glossary/diffie-hellman-key-exchange-algorithm/)
- [Wikipedia – Cryptographic Hash Function](https://en.wikipedia.org/wiki/Cryptographic_hash_function)
