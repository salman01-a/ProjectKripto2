# gunakan nama yang benar: chacha20
def generate_chacha20_key():
    return secrets.token_bytes(32)  # ChaCha20 pakai key 32 bytes

def encrypt_chacha20(text, key):
    try:
        nonce = secrets.token_bytes(16)  # <-- HARUS 16 bytes untuk cryptography.ChaCha20
        text_bytes = text.encode('utf-8')
        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(text_bytes) + encryptor.finalize()
        encrypted_data = nonce + ciphertext
        return base64.b64encode(encrypted_data).decode('utf-8')
    except Exception as e:
        st.error(f"Encryption error: {e}")
        return None

def decrypt_chacha20(encrypted_text, key):
    try:
        encrypted_data = base64.b64decode(encrypted_text.encode('utf-8'))
        nonce = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        st.error(f"Decryption error: {e}")
        return None

from Crypto.Cipher import Salsa20

def generate_salsa20_key():
    return secrets.token_bytes(32)  # Salsa20 bisa 16/32 bytes key; 32 recommended

def encrypt_salsa20_pycryptodome(text, key):
    try:
        nonce = secrets.token_bytes(8)  # Salsa20: 8 bytes nonce
        cipher = Salsa20.new(key=key, nonce=nonce)
        ciphertext = cipher.encrypt(text.encode('utf-8'))
        encrypted_data = nonce + ciphertext
        return base64.b64encode(encrypted_data).decode('utf-8')
    except Exception as e:
        st.error(f"Encryption error: {e}")
        return None

def decrypt_salsa20_pycryptodome(encrypted_text, key):
    try:
        encrypted_data = base64.b64decode(encrypted_text.encode('utf-8'))
        nonce = encrypted_data[:8]
        ciphertext = encrypted_data[8:]
        cipher = Salsa20.new(key=key, nonce=nonce)
        decrypted = cipher.decrypt(ciphertext)
        return decrypted.decode('utf-8')
    except Exception as e:
        st.error(f"Decryption error: {e}")
        return None
