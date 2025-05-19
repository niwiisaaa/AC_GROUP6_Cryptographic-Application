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
