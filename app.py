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

# ----------------- API Routes ----------------- #

@app.route('/api/xor', methods=['POST'])
def api_xor():
    data = request.json
    text = data.get('text', '')
    key = data.get('key', '')
    mode = data.get('mode', 'encrypt')

    if not text or not key:
        return jsonify({'error': 'Missing text or key'}), 400

    result = ""
    breakdown = []

    try:
        if mode == 'encrypt':
            xor_bytes = bytearray()
            for i in range(len(text)):
                pt_char = text[i]
                key_char = key[i % len(key)]
                xor_val = ord(pt_char) ^ ord(key_char)
                xor_bytes.append(xor_val)
                breakdown.append({
                    'pt_char': pt_char,
                    'pt_bin': format(ord(pt_char), '08b'),
                    'key_char': key_char,
                    'key_bin': format(ord(key_char), '08b'),
                    'xor_hex': format(xor_val, '02X')
                })
            result = ' '.join(format(b, '02X') for b in xor_bytes)

        elif mode == 'decrypt':
            try:
                hex_parts = text.strip().split()
                xor_bytes = bytes(int(h, 16) for h in hex_parts)
            except Exception:
                return jsonify({'error': 'Invalid hex input for decryption'}), 400

            out_chars = []
            for i in range(len(xor_bytes)):
                xor_val = xor_bytes[i]
                key_char = key[i % len(key)]
                pt_val = xor_val ^ ord(key_char)
                out_chars.append(chr(pt_val))
                breakdown.append({
                    'pt_char': chr(pt_val) if 32 <= pt_val <= 126 else '.',
                    'pt_bin': format(pt_val, '08b'),
                    'key_char': key_char,
                    'key_bin': format(ord(key_char), '08b'),
                    'xor_hex': format(xor_val, '02X')
                })
            result = ''.join(out_chars)
        else:
            return jsonify({'error': 'Invalid mode'}), 400

        return jsonify({'result': result, 'breakdown': breakdown})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/caesar', methods=['POST'])
def api_caesar():
    data = request.json
    text = data.get('text', '')
    shift = data.get('shift', '')
    mode = data.get('mode', 'encrypt')
    if not text or not shift:
        return jsonify({'error': 'Missing text or shift'}), 400
    try:
        result, breakdown = caesar_cipher(text, shift, mode)
        return jsonify({'result': result, 'breakdown': breakdown})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/vigenere', methods=['POST'])
def api_vigenere():
    data = request.json
    text = data.get('text', '')
    key = data.get('key', '')
    alphabet = data.get('alphabet', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    mode = data.get('mode', 'encrypt')
    if not text:
        return jsonify({'result': '', 'breakdown': []})
    if not key or not alphabet:
        # Return original text if key or alphabet is missing
        return jsonify({'result': text, 'breakdown': [{'original': c, 'key_char': '', 'shift': '', 'result': c} for c in text]})
    try:
        result, breakdown = vigenere_cipher(text, key, mode, alphabet)
        return jsonify({'result': result, 'breakdown': breakdown})
    except Exception as e:
        # Always return at least the original text as result
        return jsonify({'result': text, 'breakdown': [{'original': c, 'key_char': '', 'shift': '', 'result': c} for c in text], 'error': str(e)}), 200

@app.route('/api/hash', methods=['POST'])
def api_hash():
    data = request.json
    text = data.get('text', '')
    algo = data.get('algo', 'sha256')
    if not text:
        return jsonify({'error': 'Missing text'}), 400
    try:
        hashval = compute_hash(text, algo)
        return jsonify({'result': hashval})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rsa', methods=['POST'])
def api_rsa():
    data = request.json
    action = data.get('action')
    if action == 'generate':
        pub, priv = rsa_generate_keys()
        return jsonify({'public_key': pub, 'private_key': priv})
    elif action == 'encrypt':
        message = data.get('message', '')
        e = int(data.get('e'))
        n = int(data.get('n'))
        encrypted = rsa_encrypt(message, e, n)
        return jsonify({'encrypted': encrypted})
    elif action == 'decrypt':
        encrypted = data.get('encrypted', [])
        d = int(data.get('d'))
        n = int(data.get('n'))
        decrypted = rsa_decrypt(encrypted, d, n)
        return jsonify({'decrypted': decrypted})
    else:
        return jsonify({'error': 'Invalid action'}), 400

@app.route('/api/diffie_hellman', methods=['POST'])
def api_diffie_hellman():
    data = request.json
    action = data.get('action')
    if action == 'generate':
        params = dh_generate_params()
        return jsonify(params)
    elif action == 'encrypt':
        text = data.get('text', '')
        shared_secret = int(data.get('shared_secret'))
        encrypted = dh_xor_encrypt(text, shared_secret)
        return jsonify({'encrypted': encrypted})
    elif action == 'decrypt':
        encrypted = data.get('encrypted', [])
        shared_secret = int(data.get('shared_secret'))
        decrypted = dh_xor_decrypt(encrypted, shared_secret)
        return jsonify({'decrypted': decrypted})
    else:
        return jsonify({'error': 'Invalid action'}), 400

@app.route('/upload/block', methods=['POST'])
def upload_block():
    file = request.files.get('file')
    key = request.form.get('key', '').encode()
    mode = request.form.get('mode')
    block_size = int(request.form.get('block_size', 8))

    if not file or not key or mode not in ['encrypt', 'decrypt']:
        return jsonify({'error': 'Missing fields'}), 400

    content = file.read()

    try:
        if mode == 'encrypt':
            output_bytes = xor_block_cipher(content, key, block_size, encrypt=True)
            hex_output = ' '.join(format(b, '02X') for b in output_bytes)
            return jsonify({'result': hex_output})
        else:
            hex_parts = content.decode().strip().split()
            decoded = bytes(int(h, 16) for h in hex_parts)
            decrypted = xor_block_cipher(decoded, key, block_size, encrypt=False)
            return jsonify({'result': decrypted.decode(errors="replace")})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/upload/caesar', methods=['POST'])
def upload_caesar():
    file = request.files.get('file')
    shift = request.form.get('shift', '')
    mode = request.form.get('mode', 'encrypt')
    if not file or not shift or mode not in ['encrypt', 'decrypt']:
        return jsonify({'error': 'Missing fields'}), 400
    try:
        content = file.read().decode(errors='replace')
        result, _ = caesar_cipher(content, shift, mode)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/upload/vigenere', methods=['POST'])
def upload_vigenere():
    file = request.files.get('file')
    key = request.form.get('key', '')
    alphabet = request.form.get('alphabet', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    mode = request.form.get('mode', 'encrypt')
    if not file:
        return jsonify({'result': '', 'error': 'No file uploaded'})
    content = file.read().decode(errors='replace')
    if not key or not alphabet:
        # Return original file content if key or alphabet is missing
        return jsonify({'result': content})
    try:
        result, _ = vigenere_cipher(content, key, mode, alphabet)
        return jsonify({'result': result})
    except Exception as e:
        # Always return at least the original file content as result
        return jsonify({'result': content, 'error': str(e)}), 200

@app.route('/upload/hash', methods=['POST'])
def upload_hash():
    file = request.files.get('file')
    algo = request.form.get('algo', 'sha256')
    if not file:
        return jsonify({'error': 'No file uploaded'}), 400
    try:
        content = file.read()
        hashval = compute_hash(content, algo)
        return jsonify({'result': hashval})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ----------------- Page Routes ----------------- #

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/block_cipher_xor')
def block_cipher_xor():
    return render_template('block_cipher_xor.html')

@app.route('/caesar_cipher')
def caesar_cipher_page():
    return render_template('caesar_cipher.html')

@app.route('/vigenere')
def vigenere_page():
    return render_template('vigenere.html')

@app.route('/hash')
def hash_page():
    return render_template('hash.html')

@app.route('/rsa_basic')
def rsa_basic():
    return render_template('rsa_basic.html')

@app.route('/diffie_hellman')
def diffie_hellman_page():
    return render_template('diffie_hellman.html')

# ----------------- Run Server ----------------- #

if __name__ == '__main__':
    app.run(debug=True)
