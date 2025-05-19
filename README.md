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
- Backend: Python handles the logic for encryption, decryption, and hashing using various cryptographic libraries (e.g., pycryptodome, cryptography, rsa, hashlib).
- Integration: Each cryptographic function is mapped to a route in Flask, processing user input and displaying results dynamically.

The UI guides users through selecting an algorithm, entering or uploading data, and viewing results, with descriptions of each algorithm available within the application to promote learning and understanding.

---

### Implemented Cryptographic Algorithms

#### 1. Caesar Cipher
- **Type:** Symmetric
- **History/Background:** Caesar Cipher is one of the earliest known encryption techniques, named after Julius Caesar, who used it to protect military communications. It is a simple substitution cipher that shifts each letter in the plaintext by a fixed number of positions in the alphabet. 
- **Process:** With a given shift (e.g., 3), each letter is replaced by another letter that is three positions ahead in the alphabet (A → D, B → E, etc.). The same shift value is used for both encryption and decryption. 
- **Library:**
- **Integration:**

#### 2. Block Cipher (AES)
- **Type:** Symmetric
- **History/Background:** AES (Advanced Encryption Standard) was developed by the National Institute of Standards and Technology (NIST) in 2001, AES was introduced as the successor to DES and Triple DES. It became the encryption standard due to its balance of security, performance, and flexibility.
- **Process:** AES encrypts data in 128-bit blocks using key sizes of 128, 192, or 256 bits. It applies multiple rounds of byte substitution, row shifting, column mixing, and key addition based on the key length. 
- **Library:** 
- **Integration:** 

#### 3. Vigenère Cipher
- **Type:** Symmetric
- **History/Background:** Vigenère Cipher was first introduced by Giovan Battista Bellaso in 1553, but later popularized and named after Blaise de Vigenère in 1586. Though once believed unbreakable, it was eventually deciphered by Charles Babbage and Friedrich Kasiski using mathematical analysis.
- **Process:** Encrypts text by shifting each letter based on a repeating keyword (a series of Caesar ciphers).
- **Library:** 
- **Integration:**

#### 4. RSA
- **Type:** Asymmetric
- **History/Background:** RSA was developed in 1977 by Ron Rivest, Adi Shamir, and Leonard Adleman at Massachusetts Institute of Technology. It was designed to secure digital communication over untrusted networks. RSA solved the problem of key distribution in traditional cryptography by introducing public-key encryption.
- **Process:** Encrypts data using the recipient’s public key and decrypts it with their private key, enabling secure communication without prior key exchange.
- **Library:** 
- **Integration:**

#### 5. Diffie-Hellman
- **Type:** Asymmetric
- **History/Background:** Diffie-Hellman was introduced in 1976 by Whitfield Diffie and Martin Hellman, it was the first widely used method to securely exchange cryptographic keys over a public channel. It laid the foundation for public-key cryptography. 
- **Process:** Two parties agree on a large prime number and a base. Each party chooses a secret number, computes a public value, and exchanges it. Using the received value and their own secret, both compute the same shared secret key. 
- **Library:** 
- **Integration:**

#### 6. Hashing Functions (SHA-256, SHA-512, MD5, SHA-1)
- **Type:** Hash 
- **History/Background:** Hash functions were developed to ensure data integrity and security. MD5 was released in 1992, SHA-1 in 1995, and SHA-2 (which includes SHA-256 and SHA-512) in 2001 by the U.S. National Security Agency (NSA). 
- **Process:** Converts input data into a fixed-length hash value. Any change in the input produces a completely different hash. The process is deterministic, fast, and irreversible.
- **Library:**  
- **Integration:**

---

## 🖥️ Sample Runs/Outputs


## 📚 References

- [GeeksforGeeks – Advanced Encryption Standard (AES)](https://www.geeksforgeeks.org/advanced-encryption-standard-aes/) 
- [GeeksforGeeks – Caesar Cipher in Cryptography](https://www.geeksforgeeks.org/caesar-cipher-in-cryptography/)
- [Study.com – Vigenre Cipher History, Example & Coding Variants](https://study.com/academy/lesson/vigenere-cipher-square-decoder.html)
- [Splunk Blogs – RSA Algorithm in Cryptography: Rivest Shamir Adleman Explained](https://www.splunk.com/en_us/blog/learn/rsa-algorithm-cryptography.html)
- [1Kosmos – Diffie-Hellman Key Exchange Algorithm](https://www.1kosmos.com/security-glossary/diffie-hellman-key-exchange-algorithm/)
- [Wikipedia – Cryptographic Hash Function](https://en.wikipedia.org/wiki/Cryptographic_hash_function)
