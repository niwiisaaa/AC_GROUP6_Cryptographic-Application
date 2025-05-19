from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
import os
import hashlib
import random
import secrets

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ----------------- XOR Block Cipher Core ----------------- #

def xor_block_cipher(data: bytes, key: bytes, block_size: int = 8, encrypt=True) -> bytes:
    result = bytearray()
    key_len = len(key)

    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        if len(block) < block_size and encrypt:
            block += b' ' * (block_size - len(block))  # pad with spaces
        for j in range(len(block)):
            result.append(block[j] ^ key[j % key_len])
    return bytes(result)

# ----------------- Caesar Cipher Core ----------------- #

def caesar_cipher(text, shift, mode='encrypt'):
    result = []
    breakdown = []
    shift_vals = [int(s) for s in shift.strip().split()]
    shift_len = len(shift_vals)
    for i, c in enumerate(text):
        s = shift_vals[i % shift_len]
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            if mode == 'encrypt':
                shifted = (ord(c) - base + s) % 26 + base
            else:
                shifted = (ord(c) - base - s) % 26 + base
            result.append(chr(shifted))
            breakdown.append({'original': c, 'shift': s, 'result': chr(shifted)})
        else:
            result.append(c)
            breakdown.append({'original': c, 'shift': '', 'result': c})
    return ''.join(result), breakdown

# ----------------- Vigenère Cipher Core ----------------- #

def vigenere_cipher(text, key, mode='encrypt', alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    result = []
    breakdown = []
    alphabet = ''.join(dict.fromkeys(alphabet))  # remove duplicates, preserve order
    if not alphabet:
        # Always return the original text as result if alphabet is empty
        return text, [{'original': c, 'key_char': '', 'shift': '', 'result': c} for c in text]
    key = key.strip()
    key_indices = [alphabet.index(k) for k in key if k in alphabet]
    if not key_indices:
        # Always return the original text as result if key is invalid
        return text, [{'original': c, 'key_char': '', 'shift': '', 'result': c} for c in text]
    j = 0  # key index
    alpha_len = len(alphabet)
    for i, c in enumerate(text):
        if c in alphabet:
            k = key_indices[j % len(key_indices)]
            c_idx = alphabet.index(c)
            if mode == 'encrypt':
                shifted = (c_idx + k) % alpha_len
            else:
                shifted = (c_idx - k) % alpha_len
            result_char = alphabet[shifted]
            result.append(result_char)
            breakdown.append({
                'original': c,
                'key_char': key[j % len(key_indices)],
                'shift': k,
                'result': result_char
            })
            j += 1
        else:
            result.append(c)
            breakdown.append({
                'original': c,
                'key_char': '',
                'shift': '',
                'result': c
            })
    return ''.join(result), breakdown

# ----------------- Hashing Core ----------------- #

def compute_hash(data, algo='sha256'):
    if algo == 'sha256':
        h = hashlib.sha256()
    elif algo == 'sha512':
        h = hashlib.sha512()
    elif algo == 'md5':
        h = hashlib.md5()
    elif algo == 'sha1':
        h = hashlib.sha1()
    else:
        raise ValueError("Unsupported hash algorithm")
    if isinstance(data, str):
        data = data.encode()
    h.update(data)
    return h.hexdigest()


# ----------------- RSA Basic Core ----------------- #

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    # Extended Euclidean Algorithm
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def is_prime(n):
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0 or n % 3 == 0: return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def generate_prime(start=100, end=300):
    while True:
        p = random.randint(start, end)
        if is_prime(p):
            return p

def rsa_generate_keys():
    p = generate_prime(100, 300)
    q = generate_prime(100, 300)
    while q == p:
        q = generate_prime(100, 300)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while gcd(e, phi) != 1:
        e = random.randrange(3, phi, 2)
    d = modinv(e, phi)
    return {'e': e, 'n': n}, {'d': d, 'n': n}

def rsa_encrypt(message, e, n):
    # Encrypt each character's ordinal value
    return [pow(ord(char), e, n) for char in message]

def rsa_decrypt(encrypted, d, n):
    # Decrypt list of integers to string
    return ''.join(chr(pow(c, d, n)) for c in encrypted)

# ----------------- Diffie-Hellman Core ----------------- #

def dh_generate_params():
    # Small primes for demo; use large primes in real applications!
    p = 467  # example small prime
    g = 2    # primitive root modulo p
    a = secrets.randbelow(p-2) + 1
    b = secrets.randbelow(p-2) + 1
    A = pow(g, a, p)
    B = pow(g, b, p)
    s_a = pow(B, a, p)
    s_b = pow(A, b, p)
    return {
        'prime': p,
        'generator': g,
        'private_a': a,
        'private_b': b,
        'public_a': A,
        'public_b': B,
        'shared_key_a': s_a,
        'shared_key_b': s_b
    }

def dh_derive_key(shared_secret):
    # Derive a 32-byte key from the shared secret (for XOR)
    return hashlib.sha256(str(shared_secret).encode()).digest()

def dh_xor_encrypt(text, shared_secret):
    key = dh_derive_key(shared_secret)
    return [ord(c) ^ key[i % len(key)] for i, c in enumerate(text)]

def dh_xor_decrypt(data, shared_secret):
    key = dh_derive_key(shared_secret)
    return ''.join(chr(b ^ key[i % len(key)]) for i, b in enumerate(data))
