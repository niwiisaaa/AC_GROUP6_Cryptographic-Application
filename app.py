from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
import os
import hashlib
import random
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import cryptocode
import pyaes

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ----------------- Hashing Core ----------------- #

def compute_hash(data, algo='sha256'):
    if isinstance(data, str):
        data = data.encode()
    if algo == 'sha256':
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    elif algo == 'sha512':
        digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    elif algo == 'md5':
        digest = hashes.Hash(hashes.MD5(), backend=default_backend())
    elif algo == 'sha1':
        digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    else:
        raise ValueError("Unsupported hash algorithm")
    digest.update(data)
    return digest.finalize().hex()

# -----------------  RSA Basic Core  ----------------- #

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
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
    return [pow(ord(char), e, n) for char in message]

def rsa_decrypt(encrypted, d, n):
    return ''.join(chr(pow(c, d, n)) for c in encrypted)

# ----------------- Diffie-Hellman (pyca/cryptography) ----------------- #

def dh_generate_params_pyca():
    parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())
    private_key_a = parameters.generate_private_key()
    private_key_b = parameters.generate_private_key()
    public_key_a = private_key_a.public_key()
    public_key_b = private_key_b.public_key()
    shared_key_a = private_key_a.exchange(public_key_b)
    shared_key_b = private_key_b.exchange(public_key_a)
    return {
        'prime': parameters.parameter_numbers().p,
        'generator': parameters.parameter_numbers().g,
        'private_a': private_key_a.private_numbers().x,
        'private_b': private_key_b.private_numbers().x,
        'public_a': public_key_a.public_numbers().y,
        'public_b': public_key_b.public_numbers().y,
        'shared_key_a': int.from_bytes(shared_key_a, 'big'),
        'shared_key_b': int.from_bytes(shared_key_b, 'big')
    }


# ----------------- CAESAR CIPHER ----------------- #

def caesar_cipher(text, shift_string, mode='encrypt'):
    import string

    # Convert shift string like "2 3 2" into a list of integers
    try:
        shift_values = list(map(int, shift_string.strip().split()))
    except ValueError:
        raise ValueError("Shift must be space-separated integers.")

    if not shift_values:
        raise ValueError("No shift values provided.")

    result = ''
    breakdown = []
    alphabet = string.ascii_lowercase
    shift_index = 0

    for char in text:
        shift = shift_values[shift_index % len(shift_values)]
        if mode == 'decrypt':
            shift = -shift

        if char.isalpha():
            is_upper = char.isupper()
            base = ord('A') if is_upper else ord('a')
            new_char = chr((ord(char) - base + shift) % 26 + base)
            breakdown.append({
                'original': char,
                'shift': shift,
                'result': new_char
            })
            result += new_char
            shift_index += 1
        else:
            breakdown.append({
                'original': char,
                'shift': 0,
                'result': char
            })
            result += char

    return result, breakdown

# ----------------- VIGENERE CIPHER ----------------- #

def vigenere_cipher(text, key, mode='encrypt', alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    alphabet = alphabet.upper()
    key = key.upper()
    text = text.upper()
    key_length = len(key)
    key_index = 0
    result = ''
    breakdown = []

    for char in text:
        if char in alphabet:
            key_char = key[key_index % key_length]
            text_index = alphabet.index(char)
            key_index_value = alphabet.index(key_char)

            if mode == 'encrypt':
                shifted_index = (text_index + key_index_value) % len(alphabet)
            elif mode == 'decrypt':
                shifted_index = (text_index - key_index_value) % len(alphabet)
            else:
                raise ValueError("Mode must be 'encrypt' or 'decrypt'")

            result_char = alphabet[shifted_index]
            result += result_char
            breakdown.append({
                'original': char,
                'key_char': key_char,
                'shift': key_index_value if mode == 'encrypt' else -key_index_value,
                'result': result_char
            })

            key_index += 1
        else:
            # Non-alphabet characters are added unchanged
            result += char
            breakdown.append({
                'original': char,
                'key_char': '',
                'shift': '',
                'result': char
            })

    return result, breakdown


# ----------------- AES Block Cipher (pyaes) ----------------- #

def aes_encrypt_pyaes(plaintext, key):
    key_bytes = hashlib.sha256(key.encode()).digest()
    aes = pyaes.AESModeOfOperationCTR(key_bytes)
    ciphertext = aes.encrypt(plaintext)
    return ciphertext.hex()

def aes_decrypt_pyaes(ciphertext_hex, key):
    key_bytes = hashlib.sha256(key.encode()).digest()
    aes = pyaes.AESModeOfOperationCTR(key_bytes)
    try:
        plaintext = aes.decrypt(bytes.fromhex(ciphertext_hex))
        return plaintext.decode(errors='replace')
    except Exception:
        return "[Decryption failed]"

# ----------------- Symmetric (cryptocode) ----------------- #

def symmetric_encrypt_cryptocode(text, password):
    return cryptocode.encrypt(text, password)

def symmetric_decrypt_cryptocode(ciphertext, password):
    return cryptocode.decrypt(ciphertext, password)

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
        params = dh_generate_params_pyca()
        return jsonify(params)
    elif action == 'encrypt':
        text = data.get('text', '')
        password = str(data.get('shared_secret', ''))
        encrypted = symmetric_encrypt_cryptocode(text, password)
        return jsonify({'encrypted': encrypted})
    elif action == 'decrypt':
        ciphertext = data.get('encrypted', '')
        password = str(data.get('shared_secret', ''))
        decrypted = symmetric_decrypt_cryptocode(ciphertext, password)
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
            output_bytes = aes_encrypt_pyaes(content.decode(errors='replace'), key.decode())
            return jsonify({'result': output_bytes})
        else:
            decrypted = aes_decrypt_pyaes(content.decode(errors='replace'), key.decode())
            return jsonify({'result': decrypted})
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

if __name__ == '__main__':
    app.run(debug=True)
