import streamlit as st
import sqlite3
import hashlib
import re
import cv2
import numpy as np
from PIL import Image
import io
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
# ===== FUNGSI SALSA20 ENCRYPTION DENGAN KUNCI USER =====

def derive_salsa_key(user_key):
    """Derive 32-byte key from user input using SHA256"""
    return hashlib.sha256(user_key.encode()).digest()

def encrypt_salsa20(text, user_key):
    """Encrypt text using Salsa20 algorithm with user key"""
    try:
        # Derive key from user input
        key = derive_salsa_key(user_key)
        
        # Generate random nonce (16 bytes for Salsa20)
        nonce = secrets.token_bytes(16)
        
        # Convert text to bytes
        text_bytes = text.encode('utf-8')
        
        # Create ChaCha20 cipher
        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Encrypt the text
        ciphertext = encryptor.update(text_bytes) + encryptor.finalize()
        
        # Combine nonce + ciphertext and encode as base64
        encrypted_data = nonce + ciphertext
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    except Exception as e:
        st.error(f"Encryption error: {e}")
        return None

def decrypt_salsa20(encrypted_text, user_key):
    """Decrypt text using ChaCha20 algorithm with user key - always return result even if wrong key"""
    try:
        if not encrypted_text:
            return "[EMPTY]"
            
        # Derive key from user input
        key = derive_salsa_key(user_key)
        
        # Decode from base64
        try:
            encrypted_data = base64.b64decode(encrypted_text.encode('utf-8'))
        except Exception:
            # Try adding padding if necessary
            try:
                padding = 4 - (len(encrypted_text) % 4)
                if padding != 4:
                    encrypted_text += "=" * padding
                encrypted_data = base64.b64decode(encrypted_text.encode('utf-8'))
            except Exception as e:
                return f"[BASE64_ERROR: {str(e)}]"
        
        # Extract nonce (first 16 bytes) and ciphertext
        if len(encrypted_data) < 16:
            return f"[DATA_TOO_SHORT: {len(encrypted_data)} bytes]"
            
        nonce = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # Create ChaCha20 cipher
        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt the text
        decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Try to decode as UTF-8
        try:
            result = decrypted_bytes.decode('utf-8')
            # Check if result contains unusual characters that might indicate wrong key
            if any(ord(c) > 127 for c in result) and len(result) > 0:
                return f"[POSSIBLE_WRONG_KEY: {result}]"
            return result
        except UnicodeDecodeError:
            # Return raw bytes as string for wrong key
            return f"[DECODE_ERROR: {decrypted_bytes.hex()[:50]}...]"
    
    except Exception as e:
        return f"[DECRYPTION_ERROR: {str(e)}]"


# ===== FUNGSI CAESAR & XOR =====

def caesar_cipher(text, shift):
    result = ""
    for char in str(text):
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            shifted_char = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            result += shifted_char
        elif char.isdigit():
            shifted_digit = str((int(char) + shift) % 10)
            result += shifted_digit
        else:
            result += char
    return result

def xor_cipher(text, key):
    result = ""
    key_length = len(key)
    for i, char in enumerate(str(text)):
        key_char = key[i % key_length]
        xor_result = ord(char) ^ ord(key_char)
        result += chr(xor_result)
    return result

def xor_cipher_with_ascii(text, key):
    """XOR cipher dengan return tambahan: result string dan list ASCII"""
    result = ""
    ascii_values = []
    key_length = len(key)
    for i, char in enumerate(str(text)):
        key_char = key[i % key_length]
        xor_result = ord(char) ^ ord(key_char)
        result += chr(xor_result)
        ascii_values.append(xor_result)
    return result, ascii_values

def super_encrypt(text, caesar_key, xor_key):
    """Super encrypt dengan return tambahan untuk ASCII values"""
    caesar_result = caesar_cipher(text, caesar_key)
    final_result, ascii_values = xor_cipher_with_ascii(caesar_result, xor_key)
    return caesar_result, final_result, ascii_values

def super_decrypt(encrypted_text, caesar_key, xor_key):
    """Super decrypt dengan return tambahan untuk ASCII values"""
    xor_result, ascii_values = xor_cipher_with_ascii(encrypted_text, xor_key)
    final_result = caesar_cipher(xor_result, -caesar_key)
    return xor_result, final_result, ascii_values

# ===== FUNGSI STEGANOGRAFI =====

def text_to_binary(text):
    """Convert text to binary string"""
    binary = ''.join(format(ord(i), '08b') for i in text)
    return binary

def binary_to_text(binary):
    """Convert binary string to text"""
    text = ''
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        text += chr(int(byte, 2))
    return text

def encode_image(image, message):
    """Encode message into image using LSB steganography"""
    img_array = np.array(image)
    binary_message = text_to_binary(message) + '1111111111111110'
    
    height, width = img_array.shape[:2]
    max_chars = (height * width * 3) // 8
    if len(message) > max_chars:
        raise ValueError(f"Pesan terlalu panjang! Maksimal {max_chars} karakter untuk gambar ini.")
    
    flat = img_array.flatten()
    
    for i in range(len(binary_message)):
        if i < len(flat):
            flat[i] = (flat[i] & 0xFE) | int(binary_message[i])
    
    encoded_array = flat.reshape(img_array.shape)
    return Image.fromarray(encoded_array.astype('uint8'))

def decode_image(image):
    """Decode message from image using LSB steganography"""
    img_array = np.array(image)
    flat = img_array.flatten()
    
    binary_message = ''
    for pixel in flat:
        binary_message += str(pixel & 1)
    
    end_index = binary_message.find('1111111111111110')
    if end_index != -1:
        binary_message = binary_message[:end_index]
    
    try:
        message = binary_to_text(binary_message)
        return message
    except:
        return "Tidak dapat mendekode pesan. Mungkin gambar tidak mengandung pesan tersembunyi."

# ===== FUNGSI FILE ENCRYPTION (AES) - HASIL SELALU PDF =====

def generate_key_from_password(password, salt=None):
    """Generate encryption key from password using PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_file(file_data, password):
    """Encrypt file data using AES"""
    try:
        # Generate key from password
        key, salt = generate_key_from_password(password)
        
        # Create Fernet object
        fernet = Fernet(key)
        
        # Encrypt the data
        encrypted_data = fernet.encrypt(file_data)
        
        # Combine salt + encrypted data
        result = salt + encrypted_data
        return result, None
    except Exception as e:
        return None, str(e)

def decrypt_file(encrypted_data, password):
    """Decrypt file data using AES"""
    try:
        # Extract salt (first 16 bytes) and encrypted data
        salt = encrypted_data[:16]
        actual_encrypted_data = encrypted_data[16:]
        
        # Generate key from password
        key, _ = generate_key_from_password(password, salt)
        
        # Create Fernet object
        fernet = Fernet(key)
        
        # Decrypt the data
        decrypted_data = fernet.decrypt(actual_encrypted_data)
        return decrypted_data, None
    except Exception as e:
        return None, str(e)

def create_pdf_report(original_filename, operation_type, file_size, status):
    """Create a simple PDF report about the encryption/decryption operation"""
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    from datetime import datetime
    
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    # Title
    p.setFont("Helvetica-Bold", 16)
    p.drawString(100, height - 100, "Laporan Enkripsi/Dekripsi File")
    
    # Operation details
    p.setFont("Helvetica", 12)
    p.drawString(100, height - 140, f"Jenis Operasi: {operation_type}")
    p.drawString(100, height - 160, f"Nama File: {original_filename}")
    p.drawString(100, height - 180, f"Ukuran File: {file_size}")
    p.drawString(100, height - 200, f"Status: {status}")
    p.drawString(100, height - 220, f"Tanggal: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Security info
    p.drawString(100, height - 260, "Informasi Keamanan:")
    p.drawString(100, height - 280, "- Menggunakan algoritma AES-256")
    p.drawString(100, height - 300, "- Key derivation: PBKDF2 dengan 100,000 iterasi")
    p.drawString(100, height - 320, "- Salt random untuk setiap operasi")
    
    p.showPage()
    p.save()
    
    buffer.seek(0)
    return buffer.getvalue()

# ===== FUNGSI DATABASE & AUTH (TANPA ENKRIPSI CAESAR) =====

def hash_password(password):
    return hashlib.sha512(password.encode()).hexdigest()

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def register_user(username, password):
    try:
        hashed_password = hash_password(password)
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', 
                 (username, hashed_password))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False
    except Exception as e:
        st.error(f"Error: {e}")
        return False

def login_user(username, password):
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT password FROM users WHERE username = ?', (username,))
        result = c.fetchone()
        conn.close()
        
        if result:
            stored_hashed_password = result[0]
            hashed_input_password = hash_password(password)
            
            if hashed_input_password == stored_hashed_password:
                return True
        return False
    except Exception as e:
        st.error(f"Error: {e}")
        return False

def validate_input(username, password):
    if len(username) < 3:
        return "Username harus minimal 3 karakter"
    if len(password) < 6:
        return "Password harus minimal 6 karakter"
    if not re.match("^[a-zA-Z0-9_]+$", username):
        return "Username hanya boleh mengandung huruf, angka, dan underscore"
    return None

# ===== FUNGSI DATABASE MOBIL DENGAN ENKRIPSI SALSA20 =====

def init_car_db():
    """Initialize database for cars"""
    conn = sqlite3.connect('cars.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS cars (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model TEXT NOT NULL,
            brand TEXT NOT NULL,
            price TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# def get_salsa_key():
#     """Get or generate Salsa20 key from session state"""
#     if 'salsa_key' not in st.session_state:
#         # Generate new key if not exists
#         st.session_state.salsa_key = generate_salsa20_key()
#         st.info("🔑 Kunci enkripsi baru telah di-generate untuk session ini.")
#     return st.session_state.salsa_key

def create_car(model, brand, price, encryption_key):
    """Add new car to database with Salsa20 encryption using user key"""
    try:
        # Pastikan semua data adalah string sebelum dienkripsi
        model_str = str(model)
        brand_str = str(brand)
        price_str = str(price)
        
        # Encrypt all fields dengan kunci user
        encrypted_model = encrypt_salsa20(model_str, encryption_key)
        encrypted_brand = encrypt_salsa20(brand_str, encryption_key)
        encrypted_price = encrypt_salsa20(price_str, encryption_key)

        if not all([encrypted_model, encrypted_brand, encrypted_price]):
            st.error("Gagal mengenkripsi data! Periksa kunci dan data input.")
            return False
            
        conn = sqlite3.connect('cars.db')
        c = conn.cursor()
        c.execute('INSERT INTO cars (model, brand, price) VALUES (?, ?, ?)', 
                 (encrypted_model, encrypted_brand, encrypted_price))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Error: {e}")
        return False

def read_cars(encryption_key):
    """Get all cars from database with Salsa20 decryption - always show results even with wrong key"""
    try:
        conn = sqlite3.connect('cars.db')
        c = conn.cursor()
        c.execute('SELECT * FROM cars')
        encrypted_cars = c.fetchall()
        conn.close()
        
        # Track if we have any successful decryptions
        successful_decrypts = 0
        total_cars = len(encrypted_cars)
        
        # Decrypt all fields dengan kunci user
        decrypted_cars = []
        for car in encrypted_cars:
            car_id, encrypted_model, encrypted_brand, encrypted_price = car
            
            model = decrypt_salsa20(encrypted_model, encryption_key)
            brand = decrypt_salsa20(encrypted_brand, encryption_key)
            price = decrypt_salsa20(encrypted_price, encryption_key)
            
            # Check if any field looks like wrong key (contains error markers)
            has_errors = any(field.startswith('[') and field.endswith(']') for field in [model, brand, price])
            
            if not has_errors:
                successful_decrypts += 1
                try:
                    # Try to convert price to float for proper formatting
                    price_float = float(price)
                    decrypted_cars.append((car_id, model, brand, price_float, True))  # True = successful decrypt
                except ValueError:
                    decrypted_cars.append((car_id, model, brand, price, True))
            else:
                # Add with error flag
                decrypted_cars.append((car_id, model, brand, price, False))
                
        return decrypted_cars, successful_decrypts, total_cars
        
    except Exception as e:
        st.error(f"Error membaca data mobil: {e}")
        return [], 0, 0
    
    
def delete_car(car_id):
    """Delete car from database"""
    try:
        conn = sqlite3.connect('cars.db')
        c = conn.cursor()
        c.execute('DELETE FROM cars WHERE id = ?', (car_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Error: {e}")
        return False

# ===== PAGE DEFINITIONS =====

def page_super_encryption():
    st.header("🔐 Super Enkripsi - Caesar + XOR")
    st.write("Tool untuk enkripsi dan dekripsi menggunakan kombinasi Caesar Cipher dan XOR Cipher")
    
    mode = st.radio("Pilih Mode:", ["Enkripsi", "Dekripsi"])
    text_input = st.text_area("Masukkan teks:")
    
    col1, col2 = st.columns(2)
    
    with col1:
        caesar_key = st.number_input(
            "Kunci Caesar:", 
            min_value=-100, 
            max_value=100, 
            value=1,
            help="Range kunci: -100 sampai 100"
        )
    
    with col2:
        xor_key = st.text_input(
            "Kunci XOR:", 
            value="secret",
            help="Kunci berupa string"
        )
    
    # Checkbox untuk menampilkan detail ASCII
    show_ascii = st.checkbox("📊 Tampilkan Detail ASCII", value=True,
                           help="Tampilkan representasi ASCII dari setiap step")
    
    if st.button(f"🚀 Jalankan {mode}"):
        if not text_input:
            st.warning("Masukkan teks terlebih dahulu!")
            return
        
        if not xor_key:
            st.warning("Masukkan kunci XOR!")
            return
        
        if mode == "Enkripsi":
            st.subheader("🔒 Hasil Enkripsi")
            caesar_result, final_result, ascii_values = super_encrypt(text_input, caesar_key, xor_key)
            
            # Tampilkan step-by-step process
            col_step1, col_step2 = st.columns(2)
            
            with col_step1:
                st.write("**Step 1 - Caesar Cipher:**")
                st.code(f"Input: {text_input}")
                st.code(f"Setelah Caesar (shift {caesar_key}): {caesar_result}")
                
                if show_ascii:
                    st.write("**ASCII Caesar Result:**")
                    caesar_ascii = [ord(c) for c in caesar_result]
                    st.code(caesar_ascii)
                    st.caption(f"Panjang: {len(caesar_ascii)} karakter")
            
            with col_step2:
                st.write("**Step 2 - XOR Cipher:**")
                st.code(f"Setelah XOR (kunci '{xor_key}'): {final_result}")
                
                if show_ascii:
                    st.write("**ASCII XOR Result:**")
                    st.code(ascii_values)
                    st.caption(f"Panjang: {len(ascii_values)} karakter")
                    
                    # Tampilkan detail per karakter
                    with st.expander("🔍 Detail Per Karakter XOR"):
                        st.write("**Proses XOR per karakter:**")
                        for i, char in enumerate(caesar_result):
                            if i < len(ascii_values):
                                key_char = xor_key[i % len(xor_key)]
                                st.write(f"`{char}` (ASCII: {ord(char):3d}) XOR `{key_char}` (ASCII: {ord(key_char):3d}) = `{final_result[i]}` (ASCII: {ascii_values[i]:3d})")
            
            st.write("**🎯 Hasil Final Enkripsi:**")
            st.success(final_result)
            
            # Tampilkan dalam berbagai format
            with st.expander("📋 Hasil dalam Format Lain"):
                col_format1, col_format2 = st.columns(2)
                
                with col_format1:
                    st.write("**Hexadecimal:**")
                    hex_result = ' '.join([f"{b:02x}" for b in ascii_values])
                    st.code(hex_result)
                    
                    st.write("**Binary:**")
                    binary_result = ' '.join([format(b, '08b') for b in ascii_values])
                    st.code(binary_result)
                
                with col_format2:
                    st.write("**Decimal (untuk programming):**")
                    st.code(str(ascii_values))
                    
                    st.write("**Panjang Data:**")
                    st.info(f"Input: {len(text_input)} karakter → Output: {len(final_result)} karakter")
            
            st.text_input("Salin hasil enkripsi:", value=final_result, key="encrypted_result")
            
        else:  # Mode Dekripsi
            st.subheader("🔓 Hasil Dekripsi")
            xor_result, final_result, ascii_values = super_decrypt(text_input, caesar_key, xor_key)
            
            # Tampilkan step-by-step process
            col_step1, col_step2 = st.columns(2)
            
            with col_step1:
                st.write("**Step 1 - XOR Decrypt:**")
                st.code(f"Input: {text_input}")
                st.code(f"Setelah XOR (kunci '{xor_key}'): {xor_result}")
                
                if show_ascii:
                    st.write("**ASCII XOR Result:**")
                    st.code(ascii_values)
                    st.caption(f"Panjang: {len(ascii_values)} karakter")
                    
                    # Tampilkan detail per karakter untuk XOR decrypt
                    with st.expander("🔍 Detail Per Karakter XOR Decrypt"):
                        st.write("**Proses XOR per karakter:**")
                        input_ascii = [ord(c) for c in text_input]
                        for i, char in enumerate(text_input):
                            if i < len(ascii_values) and i < len(xor_result):
                                key_char = xor_key[i % len(xor_key)]
                                st.write(f"`{char}` (ASCII: {input_ascii[i]:3d}) XOR `{key_char}` (ASCII: {ord(key_char):3d}) = `{xor_result[i]}` (ASCII: {ascii_values[i]:3d})")
            
            with col_step2:
                st.write("**Step 2 - Caesar Decrypt:**")
                st.code(f"Setelah Caesar (shift -{caesar_key}): {final_result}")
                
                if show_ascii:
                    st.write("**ASCII Final Result:**")
                    final_ascii = [ord(c) for c in final_result]
                    st.code(final_ascii)
                    st.caption(f"Panjang: {len(final_ascii)} karakter")
            
            st.write("**🎯 Hasil Final Dekripsi:**")
            st.success(final_result)
            
            # Validasi hasil
            if show_ascii:
                with st.expander("✅ Validasi Hasil"):
                    # Test dengan enkripsi ulang untuk validasi
                    test_encrypted, _, _ = super_encrypt(final_result, caesar_key, xor_key)
                    if test_encrypted == text_input:
                        st.success("✅ Validasi berhasil: Enkripsi ulang menghasilkan input awal!")
                    else:
                        st.warning("⚠️ Validasi gagal: Hasil dekripsi mungkin tidak akurat")
                        st.write(f"Input awal: {text_input}")
                        st.write(f"Enkripsi ulang: {test_encrypted}")
            
            st.text_input("Salin hasil dekripsi:", value=final_result, key="decrypted_result")

def page_car_database():
    st.header("🚗 Database Mobil dengan Enkripsi Salsa20")
    st.write("Kelola data mobil dengan enkripsi Salsa20 - **Data akan tetap ditampilkan meski kunci salah**")
    
    # Initialize car database
    init_car_db()
    
    # Input kunci enkripsi dari user
    st.subheader("🔑 Kunci Enkripsi")
    col1, col2 = st.columns([3, 1])
    
    with col1:
        encryption_key = st.text_input(
            "Masukkan Kunci Enkripsi:", 
            type="password",
            placeholder="Kunci yang sama harus digunakan untuk encrypt dan decrypt",
            help="Coba kunci berbeda untuk melihat efeknya pada data terdekripsi!"
        )
    
    with col2:
        show_encrypted = st.checkbox("Tampilkan Data Terenkripsi", help="Lihat data asli di database")
    
    if not encryption_key:
        st.warning("⚠️ Silakan masukkan kunci enkripsi untuk mengakses database mobil.")
        st.info("""
        **Fitur Baru:**
        - Data akan tetap ditampilkan meski kunci salah
        - Anda bisa melihat bagaimana kunci yang berbeda menghasilkan data terdekripsi yang berbeda
        - Kunci yang benar akan menampilkan data yang bermakna
        """)
        
        # Tampilkan data terenkripsi saja jika checkbox dicentang
        if show_encrypted:
            display_encrypted_data_only()
        return
    
    # Info tentang status kunci
    with st.expander("ℹ️ Status Kunci & Enkripsi"):
        st.write(f"""
        **Kunci Saat Ini:** `{encryption_key[:8]}...` (panjang: {len(encryption_key)} karakter)
        
        **Cara Kerja:**
        - Setiap kunci akan menghasilkan output dekripsi yang berbeda
        - Hanya kunci yang benar yang akan menampilkan data asli
        - Kunci salah akan menampilkan karakter acak atau pesan error
        """)
        
        # Test kunci
        if st.button("🧪 Test Kunci Ini"):
            test_text = "Data testing 123"
            encrypted = encrypt_salsa20(test_text, encryption_key)
            if encrypted:
                decrypted = decrypt_salsa20(encrypted, encryption_key)
                st.write(f"**Test Enkripsi/Deskripsi:**")
                st.write(f"Original: `{test_text}`")
                st.write(f"Terenkripsi: `{encrypted[:50]}...`")
                st.write(f"Terdekripsi: `{decrypted}`")
                
                if decrypted == test_text:
                    st.success("✅ Kunci berfungsi dengan baik!")
                else:
                    st.warning("⚠️ Kunci menghasilkan output yang tidak sesuai!")

    tab1, tab2 = st.tabs(["➕ Tambah Mobil", "📋 Lihat & Hapus Mobil"])
    
    with tab1:
        st.subheader("Tambah Mobil Baru (Terenkripsi)")
        
        with st.form("add_car_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                brand = st.text_input("Brand Mobil", placeholder="Contoh: Toyota, Honda, dll.")
                model = st.text_input("Model Mobil", placeholder="Contoh: Camry, Civic, dll.")
            
            with col2:
                price = st.number_input("Harga Mobil (Rp)", min_value=0, step=1000000, 
                                      format="%d", value=100000000)
            
            submit_button = st.form_submit_button("💾 Simpan Mobil (Terenkripsi)")
            
            if submit_button:
                if not brand or not model:
                    st.error("Brand dan Model harus diisi!")
                elif price <= 0:
                    st.error("Harga harus lebih dari 0!")
                else:
                    if create_car(model, brand, price, encryption_key):
                        st.success(f"✅ Mobil {brand} {model} berhasil ditambahkan dengan enkripsi!")
                        
                        # Tampilkan perbandingan enkripsi
                        with st.expander("🔍 Lihat Detail Enkripsi"):
                            st.write("**Data sebelum enkripsi:**")
                            st.code(f"Brand: {brand}\nModel: {model}\nHarga: Rp {price:,}")
                            
                            enc_brand = encrypt_salsa20(brand, encryption_key)
                            enc_model = encrypt_salsa20(model, encryption_key)
                            enc_price = encrypt_salsa20(str(price), encryption_key)
                            
                            st.write("**Data setelah enkripsi (disimpan di database):**")
                            st.code(f"Brand: {enc_brand}\nModel: {enc_model}\nHarga: {enc_price}")
                    else:
                        st.error("❌ Gagal menambahkan mobil!")
    
    with tab2:
        st.subheader("Daftar Mobil (Hasil Dekripsi)")
        
        # Dapatkan data mobil
        cars, successful_decrypts, total_cars = read_cars(encryption_key)
        
        # Tampilkan status dekripsi
        if total_cars > 0:
            if successful_decrypts == total_cars:
                st.success(f"✅ Semua {total_cars} mobil berhasil didekripsi dengan kunci ini!")
            elif successful_decrypts > 0:
                st.warning(f"⚠️ {successful_decrypts} dari {total_cars} mobil berhasil didekripsi. Beberapa data mungkin menggunakan kunci berbeda.")
            else:
                st.error(f"❌ Tidak ada data yang berhasil didekripsi dengan kunci ini. Kemungkinan kunci salah!")
        
        if not cars:
            st.info("📝 Belum ada data mobil. Silakan tambah mobil baru di tab 'Tambah Mobil'.")
        else:
            st.write(f"**Menampilkan {len(cars)} mobil:**")
            
            for car in cars:
                car_id, model, brand, price, decrypt_success = car
                
                with st.container():
                    # Tampilkan border warna berdasarkan status dekripsi
                    if decrypt_success:
                        st.markdown(f'<div style="border-left: 4px solid #00ff00; padding-left: 10px;">', unsafe_allow_html=True)
                    else:
                        st.markdown(f'<div style="border-left: 4px solid #ff0000; padding-left: 10px;">', unsafe_allow_html=True)
                    
                    col1, col2, col3 = st.columns([3, 2, 1])
                    
                    with col1:
                        if decrypt_success:
                            st.write(f"**Brand:{brand} \t Model:{model}**")
                        else:
                            st.write(f"~~{brand} {model}~~")
                        st.caption(f"ID: {car_id}")
                        if not decrypt_success:
                            st.error("⚠️ Gagal dekripsi - kunci mungkin salah")
                    
                    with col2:
                        if isinstance(price, (int, float)):
                            st.write(f"**Harga:** Rp {price:,.0f}")
                        else:
                            st.write(f"**Harga:** {price}")
                    
                    with col3:
                        if st.button(f"🗑️ Hapus", key=f"delete_{car_id}"):
                            if delete_car(car_id) & decrypt_success:
                                st.success(f"✅ Data mobil berhasil dihapus!")
                                st.rerun()
                            else:
                                st.error("❌ Gagal menghapus mobil!")
                    
                    st.markdown('</div>', unsafe_allow_html=True)
                    st.divider()
        
        # Tampilkan data terenkripsi jika diminta
        if show_encrypted:
            display_encrypted_data()

def display_encrypted_data():
    """Display raw encrypted data from database"""
    st.subheader("🔐 Data Terenkripsi di Database")
    
    try:
        conn = sqlite3.connect('cars.db')
        c = conn.cursor()
        c.execute('SELECT * FROM cars')
        encrypted_cars = c.fetchall()
        conn.close()
        
        if not encrypted_cars:
            st.info("Tidak ada data terenkripsi di database.")
            return
            
        for car in encrypted_cars:
            car_id, encrypted_model, encrypted_brand, encrypted_price = car
            
            with st.expander(f"Data Terenkripsi - Mobil ID {car_id}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("**Model:**")
                    st.code(encrypted_model)
                    st.write(f"Panjang: {len(encrypted_model)} karakter")
                
                with col2:
                    st.write("**Brand:**")
                    st.code(encrypted_brand)
                    st.write(f"Panjang: {len(encrypted_brand)} karakter")
                
                st.write("**Harga:**")
                st.code(encrypted_price)
                st.write(f"Panjang: {len(encrypted_price)} karakter")
                
    except Exception as e:
        st.error(f"Error mengambil data terenkripsi: {e}")

def display_encrypted_data_only():
    """Display only encrypted data when no key is provided"""
    st.subheader("🔐 Data Terenkripsi di Database")
    st.info("Masukkan kunci untuk mencoba mendekripsi data berikut:")
    
    display_encrypted_data()

def page_steganography():
    st.header("🖼️ Steganografi - Sembunyikan Pesan/Gambar dalam Gambar")
    st.write("Teknik untuk menyembunyikan pesan rahasia atau gambar dalam gambar tanpa mengubah penampilan visual")
    
    # ===== FUNGSI BARU UNTUK GAMBAR DALAM GAMBAR =====
    
    def encode_image_in_image(host_image: Image.Image, secret_image: Image.Image) -> Image.Image:

        if not isinstance(host_image, Image.Image) or not isinstance(secret_image, Image.Image):
            raise ValueError("Input harus berupa objek PIL Image")
            
        host_image = host_image.convert('RGB')
        secret_image = secret_image.convert('RGB')
        
        host_arr = np.array(host_image, dtype=np.uint8)
        secret_arr = np.array(secret_image, dtype=np.uint8)
        
        max_bytes = (host_arr.size * 1) // 8  # 1 bit per byte
        if secret_arr.size > max_bytes * 8:
            raise ValueError("Gambar rahasia terlalu besar untuk disembunyikan dalam gambar host")
        
        new_height = int(np.sqrt(max_bytes / 3))  # 3 untuk RGB channels
        new_width = new_height
        secret_img = secret_image.resize((new_width, new_height))
        secret_arr = np.array(secret_img, dtype=np.uint8)
        
        # Simpan dimensi asli untuk decoding
        width, height = secret_arr.shape[:2]
        dimension_bits = format(width, '016b') + format(height, '016b')
        
        # Konversi secret image ke binary string
        binary_secret = dimension_bits + ''.join([format(pixel, '08b') for pixel in secret_arr.flatten()])
        
        # Modify LSB dari host image
        host_flat = host_arr.flatten()
        for i in range(len(binary_secret)):
            if i < len(host_flat):
                host_flat[i] = (host_flat[i] & 254) | int(binary_secret[i])
                
        # Reshape kembali ke dimensi asli
        stego_arr = host_flat.reshape(host_arr.shape)
        return Image.fromarray(stego_arr)
    def decode_image_from_image(stego_image: Image.Image) -> Image.Image:
        # Validasi input
        if not isinstance(stego_image, Image.Image):
            raise ValueError("Input harus berupa objek PIL Image")
            
        # Konversi ke RGB jika belum
        stego_image = stego_image.convert('RGB')
        stego_arr = np.array(stego_image)
        
        # Ekstrak LSB
        binary_data = ''.join([format(pixel & 1, '01b') for pixel in stego_arr.flatten()])
        
        # Ekstrak dimensi original
        width = int(binary_data[:16], 2)
        height = int(binary_data[16:32], 2)
        binary_secret = binary_data[32:]
        
        # Validasi dimensi
        if width <= 0 or height <= 0:
            raise ValueError("Dimensi tidak valid dalam data tersembunyi")
        
        # Konversi binary ke pixels
        secret_pixels = []
        for i in range(0, len(binary_secret), 8):
            if i + 8 <= len(binary_secret):
                pixel = int(binary_secret[i:i+8], 2)
                secret_pixels.append(pixel)
        
        # Buat array dengan dimensi yang benar
        try:
            secret_arr = np.array(secret_pixels[:width*height*3], dtype=np.uint8)
            secret_arr = secret_arr.reshape((width, height, 3))
            return Image.fromarray(secret_arr)
        except ValueError as e:
            raise ValueError(f"Gagal mengekstrak gambar: {str(e)}")
    # ===== TAB DEFINITIONS =====
    
    tab1, tab2, tab3, tab4 = st.tabs(["🔒 Encode Pesan", "🔓 Decode Pesan", "🖼️ Encode Gambar", "🔍 Decode Gambar"])
    
    # ===== TAB 1: ENCODE TEKS =====
    with tab1:
        st.subheader("Sembunyikan Pesan Teks dalam Gambar")
        
        uploaded_file = st.file_uploader("Pilih gambar cover:", type=['png', 'jpg', 'jpeg'], key="encode_text")
        
        if uploaded_file is not None:
            image = Image.open(uploaded_file)
            st.image(image, caption="Gambar Cover", use_container_width=True)
            
            secret_message = st.text_area("Pesan rahasia yang akan disembunyikan:", key="text_secret")
            
            if st.button("🔄 Encode Pesan ke Gambar", key="btn_encode_text"):
                if secret_message:
                    try:
                        encoded_image = encode_image(image, secret_message)
                        
                        st.image(encoded_image, caption="Gambar dengan Pesan Tersembunyi", use_container_width=True)
                        
                        buf = io.BytesIO()
                        encoded_image.save(buf, format='PNG')
                        st.download_button(
                            label="📥 Download Gambar dengan Pesan Tersembunyi",
                            data=buf.getvalue(),
                            file_name="encoded_image.png",
                            mime="image/png"
                        )
                        
                        st.success("✅ Pesan berhasil disembunyikan dalam gambar!")
                        
                    except ValueError as e:
                        st.error(f"❌ {e}")
                    except Exception as e:
                        st.error(f"❌ Terjadi error: {e}")
                else:
                    st.warning("⚠️ Masukkan pesan terlebih dahulu!")
    
    # ===== TAB 2: DECODE TEKS =====
    with tab2:
        st.subheader("Baca Pesan Teks dari Gambar")
        
        encoded_file = st.file_uploader("Pilih gambar dengan pesan tersembunyi:", type=['png', 'jpg', 'jpeg'], key="decode_text")
        
        if encoded_file is not None:
            image = Image.open(encoded_file)
            st.image(image, caption="Gambar dengan Pesan Tersembunyi", use_container_width=True)
            
            if st.button("🔍 Decode Pesan dari Gambar", key="btn_decode_text"):
                try:
                    decoded_message = decode_image(image)
                    
                    st.subheader("📜 Pesan yang Ditemukan:")
                    st.text_area("Pesan rahasia:", value=decoded_message, height=150, key="decoded_text_area")
                    
                    if decoded_message.startswith("Tidak dapat"):
                        st.warning("⚠️ " + decoded_message)
                    else:
                        st.success("✅ Pesan berhasil diekstrak!")
                        
                except Exception as e:
                    st.error(f"❌ Terjadi error: {e}")
    
    # ===== TAB 3: ENCODE GAMBAR =====
    with tab3:
        st.subheader("Sembunyikan Gambar dalam Gambar")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Gambar Cover** (gambar yang akan dilihat)")
            cover_image = st.file_uploader("Pilih gambar cover:", type=['png', 'jpg', 'jpeg'], key="cover_img")
            
        with col2:
            st.write("**Gambar Rahasia** (gambar yang akan disembunyikan)")
            secret_image = st.file_uploader("Pilih gambar rahasia:", type=['png', 'jpg', 'jpeg'], key="secret_img")
        
        if cover_image and secret_image:
            # Display both images
            col1, col2 = st.columns(2)
            
            with col1:
                cover_img = Image.open(cover_image)
                st.image(cover_img, caption="Gambar Cover", use_container_width=True)
                st.write(f"Ukuran: {cover_img.size[0]} x {cover_img.size[1]}")
            
            with col2:
                secret_img = Image.open(secret_image)
                st.image(secret_img, caption="Gambar Rahasia", use_container_width=True)
                st.write(f"Ukuran: {secret_img.size[0]} x {secret_img.size[1]}")
            
            # Check if secret image is smaller than cover image
            if secret_img.size[0] > cover_img.size[0] or secret_img.size[1] > cover_img.size[1]:
                st.error("❌ Gambar rahasia harus lebih kecil dari gambar cover!")
            else:
                if st.button("🖼️ Sembunyikan Gambar", key="btn_encode_img"):
                    try:
                        with st.spinner("🔄 Menyembunyikan gambar..."):
                            # Encode secret image into cover image
                            result_image = encode_image_in_image(cover_img, secret_img)
                            
                            st.success("✅ Gambar berhasil disembunyikan!")
                            
                            # Display result
                            st.image(result_image, caption="Gambar dengan Gambar Tersembunyi", use_container_width=True)
                            
                            # Download button
                            buf = io.BytesIO()
                            result_image.save(buf, format='PNG')
                            st.download_button(
                                label="📥 Download Gambar dengan Gambar Tersembunyi",
                                data=buf.getvalue(),
                                file_name="image_in_image.png",
                                mime="image/png"
                            )
                            
                    except Exception as e:
                        st.error(f"❌ Terjadi error: {e}")
    
    # ===== TAB 4: DECODE GAMBAR =====
    with tab4:
        st.subheader("Ekstrak Gambar dari Gambar")
        
        st.write("Upload gambar yang berisi gambar tersembunyi:")
        encoded_image_file = st.file_uploader("Pilih gambar encoded:", type=['png', 'jpg', 'jpeg'], key="decode_img")
        
        if encoded_image_file is not None:
            encoded_img = Image.open(encoded_image_file)
            st.image(encoded_img, caption="Gambar Encoded", use_container_width=True)
            
            if st.button("🔍 Ekstrak Gambar Rahasia", key="btn_decode_img"):
                try:
                    with st.spinner("🔄 Mengekstrak gambar rahasia..."):
                        # Decode secret image from cover image
                        secret_img_extracted = decode_image_from_image(encoded_img)
                        
                        st.success("✅ Gambar rahasia berhasil diekstrak!")
                        
                        # Display extracted image
                        st.image(secret_img_extracted, caption="Gambar Rahasia yang Ditemukan", use_container_width=True)
                        
                        # Download button for extracted image
                        buf = io.BytesIO()
                        secret_img_extracted.save(buf, format='PNG')
                        st.download_button(
                            label="📥 Download Gambar Rahasia",
                            data=buf.getvalue(),
                            file_name="extracted_secret_image.png",
                            mime="image/png"
                        )
                        
                except Exception as e:
                    st.error(f"❌ Terjadi error: {e}")
                    st.error("Mungkin gambar tidak mengandung gambar tersembunyi.")
    
    st.write("---")
    st.subheader("ℹ️ Tentang Steganografi")
    st.write("""
    **Cara Kerja LSB (Least Significant Bit):**
    - Setiap pixel gambar terdiri dari 3 warna (Red, Green, Blue)
    - Setiap warna diwakili oleh angka 0-255 (8 bit)
    - Teknik LSB mengganti bit terakhir setiap warna dengan bit data rahasia
    - Perubahan ini tidak terlihat oleh mata manusia
    """)

def page_file_encryption():
    st.header("📁 Enkripsi File - AES Encryption")
    st.write("Enkripsi file dengan algoritma AES yang aman menggunakan password - **Hasil selalu format PDF**")
    
    tab1, tab2 = st.tabs(["🔒 Enkripsi File", "🔓 Dekripsi File"])
    
    with tab1:
        st.subheader("Enkripsi File")
        
        # Upload file untuk dienkripsi
        file_to_encrypt = st.file_uploader("Pilih file untuk dienkripsi:", 
                                         type=['txt', 'pdf', 'docx', 'xlsx', 'jpg', 'png', 'zip', 'rar'],
                                         key="encrypt_upload")
        
        if file_to_encrypt is not None:
            # Tampilkan info file
            file_details = {
                "Nama File": file_to_encrypt.name,
                "Tipe File": file_to_encrypt.type,
                "Ukuran File": f"{file_to_encrypt.size / 1024:.2f} KB"
            }
            st.write("**📊 Informasi File:**")
            st.json(file_details)
            
            # Input password untuk enkripsi
            encrypt_password = st.text_input("Password untuk enkripsi:", type="password", key="encrypt_pass")
            confirm_password = st.text_input("Konfirmasi password:", type="password", key="confirm_pass")
            
            if st.button("🔐 Enkripsi File", type="primary"):
                if not encrypt_password:
                    st.error("❌ Masukkan password untuk enkripsi!")
                    return
                
                if encrypt_password != confirm_password:
                    st.error("❌ Password dan konfirmasi password tidak cocok!")
                    return
                
                if len(encrypt_password) < 4:
                    st.error("❌ Password harus minimal 4 karakter!")
                    return
                
                # Baca file data
                file_data = file_to_encrypt.getvalue()
                
                # Enkripsi file
                with st.spinner("🔄 Sedang mengenkripsi file..."):
                    encrypted_data, error = encrypt_file(file_data, encrypt_password)
                
                if error:
                    st.error(f"❌ Gagal mengenkripsi file: {error}")
                else:
                    st.success("✅ File berhasil dienkripsi!")
                    
                    # Buat PDF report
                    pdf_report = create_pdf_report(
                        original_filename=file_to_encrypt.name,
                        operation_type="ENKRIPSI",
                        file_size=f"{file_to_encrypt.size / 1024:.2f} KB",
                        status="BERHASIL"
                    )
                    
                    # Download file terenkripsi sebagai PDF
                    original_name = file_to_encrypt.name
                    encrypted_pdf_name = f"encrypted_{os.path.splitext(original_name)[0]}.pdf"
                    
                    st.download_button(
                        label="📥 Download File Terenkripsi (PDF)",
                        data=encrypted_data,
                        file_name=encrypted_pdf_name,
                        mime="application/pdf"
                    )
                    
                    # Download PDF report
                    st.download_button(
                        label="📋 Download Laporan Enkripsi (PDF)",
                        data=pdf_report,
                        file_name=f"laporan_enkripsi_{os.path.splitext(original_name)[0]}.pdf",
                        mime="application/pdf"
                    )
                    
                    # Info keamanan
                    st.info("""
                    **💡 Informasi:**
                    - File hasil enkripsi disimpan dalam format PDF
                    - Simpan password dengan aman! File tidak bisa didekripsi tanpa password
                    - File asli telah diamankan dengan algoritma AES-256
                    """)
    
    with tab2:
        st.subheader("Dekripsi File")
        
        # Upload file terenkripsi
        encrypted_file = st.file_uploader("Pilih file PDF terenkripsi:", 
                                        type=['pdf'],
                                        key="decrypt_upload")
        
        if encrypted_file is not None:
            st.write(f"**File:** {encrypted_file.name}")
            
            # Input password untuk dekripsi
            decrypt_password = st.text_input("Password untuk dekripsi:", type="password", key="decrypt_pass")
            
            # Input nama file asli (opsional)
            original_filename = st.text_input("Nama file asli (optional):", 
                                            help="Jika dikosongkan, akan menggunakan nama default")
            
            if st.button("🔓 Dekripsi File", type="primary"):
                if not decrypt_password:
                    st.error("❌ Masukkan password untuk dekripsi!")
                    return
                
                # Baca file terenkripsi
                encrypted_data = encrypted_file.getvalue()
                
                # Dekripsi file
                with st.spinner("🔄 Sedang mendekripsi file..."):
                    decrypted_data, error = decrypt_file(encrypted_data, decrypt_password)
                
                if error:
                    st.error(f"❌ Gagal mendekripsi file: {error}")
                    st.error("Kemungkinan password salah atau file corrupt!")
                else:
                    st.success("✅ File berhasil didekripsi!")
                    
                    # Buat PDF report untuk dekripsi
                    pdf_report = create_pdf_report(
                        original_filename=encrypted_file.name,
                        operation_type="DEKRIPSI",
                        file_size=f"{encrypted_file.size / 1024:.2f} KB",
                        status="BERHASIL"
                    )
                    
                    # Tentukan nama file output
                    if original_filename:
                        output_filename = original_filename
                    else:
                        # Coba ekstrak dari nama file encrypted
                        if encrypted_file.name.startswith("encrypted_") and encrypted_file.name.endswith(".pdf"):
                            output_filename = encrypted_file.name[10:-4]  # Hapus "encrypted_" dan ".pdf"
                        else:
                            output_filename = f"decrypted_{encrypted_file.name[:-4]}"
                    
                    # Tentukan MIME type berdasarkan ekstensi
                    file_extension = os.path.splitext(output_filename)[1].lower()
                    mime_types = {
                        '.txt': 'text/plain',
                        '.pdf': 'application/pdf',
                        '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                        '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                        '.jpg': 'image/jpeg',
                        '.jpeg': 'image/jpeg',
                        '.png': 'image/png',
                        '.zip': 'application/zip',
                        '.rar': 'application/vnd.rar'
                    }
                    
                    mime_type = mime_types.get(file_extension, 'application/octet-stream')
                    
                    # Download file terdekripsi
                    st.download_button(
                        label="📥 Download File Terdekripsi",
                        data=decrypted_data,
                        file_name=output_filename,
                        mime=mime_type
                    )
                    
                    # Download PDF report dekripsi
                    st.download_button(
                        label="📋 Download Laporan Dekripsi (PDF)",
                        data=pdf_report,
                        file_name=f"laporan_dekripsi_{os.path.splitext(output_filename)[0]}.pdf",
                        mime="application/pdf"
                    )
    
    st.write("---")
    st.subheader("ℹ️ Tentang Sistem Enkripsi File")
    st.write("""
    **Fitur Utama:**
    - 🔒 **Enkripsi AES-256** - Standar keamanan tinggi
    - 📄 **Hasil selalu PDF** - Format seragam untuk semua file
    - 📋 **Laporan PDF** - Dokumentasi setiap operasi
    - 🔑 **Password-based** - Aman dan mudah digunakan
    
    **Alur Kerja:**
    1. Upload file apa saja (txt, pdf, docx, jpg, dll)
    2. File dienkripsi dengan AES-256
    3. Hasil enkripsi disimpan sebagai file PDF
    4. Download file PDF terenkripsi + laporan PDF
    5. Untuk dekripsi: upload file PDF terenkripsi
    6. File didekripsi ke format asli
    """)

# ===== MAIN APP =====

def main():
    st.set_page_config(page_title="Super Encryption App", page_icon="🔐", layout="wide")
    
    # Initialize database
    init_db()
    
    # Session state untuk login dan page
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'username' not in st.session_state:
        st.session_state.username = ""
    if 'current_page' not in st.session_state:
        st.session_state.current_page = "Super Encryption"
    
    # Jika belum login, tampilkan form login/register
    if not st.session_state.logged_in:
        show_login_register()
        return
    
    # Jika sudah login, tampilkan navigasi dan konten
    show_main_app()

def show_login_register():
    st.title("🔐 Aplikasi Login & Register")
    
    tab1, tab2 = st.tabs(["🔑 Login", "📝 Register"])
    
    with tab1:
        st.header("Login")
        with st.form("login_form"):
            login_username = st.text_input("Username")
            login_password = st.text_input("Password", type="password")
            login_submit = st.form_submit_button("Login")
            
            if login_submit:
                if login_username and login_password:
                    if login_user(login_username, login_password):
                        st.session_state.logged_in = True
                        st.session_state.username = login_username
                        st.session_state.current_page = "Super Encryption"
                        st.success("Login berhasil!")
                        st.rerun()
                    else:
                        st.error("Username atau password salah!")
                else:
                    st.error("Harap isi semua field!")
    
    with tab2:
        st.header("Register")
        with st.form("register_form"):
            reg_username = st.text_input("Username", key="reg_user")
            reg_password = st.text_input("Password", type="password", key="reg_pass")
            reg_confirm = st.text_input("Konfirmasi Password", type="password", key="reg_conf")
            reg_submit = st.form_submit_button("Register")
            
            if reg_submit:
                if reg_username and reg_password and reg_confirm:
                    if reg_password != reg_confirm:
                        st.error("Password dan konfirmasi password tidak cocok!")
                    else:
                        validation_error = validate_input(reg_username, reg_password)
                        if validation_error:
                            st.error(validation_error)
                        else:
                            if register_user(reg_username, reg_password):
                                st.success("Registrasi berhasil! Silakan login.")
                            else:
                                st.error("Username sudah terdaftar!")
                else:
                    st.error("Harap isi semua field!")

def show_main_app():
    # Sidebar navigation
    with st.sidebar:
        st.title("🧭 Navigasi")
        st.write(f"Selamat datang, **{st.session_state.username}**!")
        
        # Pilihan halaman (URUTAN BARU)
        page_options = ["Super Encryption", "Database Mobil", "Steganografi", "File Encryption"]
        selected_page = st.radio("Pilih Halaman:", page_options, 
                               index=page_options.index(st.session_state.current_page))
        
        # Update current page
        if selected_page != st.session_state.current_page:
            st.session_state.current_page = selected_page
            st.rerun()
        
        st.write("---")
        if st.button("🚪 Logout"):
            st.session_state.logged_in = False
            st.session_state.username = ""
            st.session_state.pop('salsa_key', None)  # Hapus kunci saat logout
            st.rerun()
    
    # Tampilkan konten berdasarkan halaman yang dipilih
    if st.session_state.current_page == "Super Encryption":
        page_super_encryption()
    elif st.session_state.current_page == "Database Mobil":
        page_car_database()
    elif st.session_state.current_page == "Steganografi":
        page_steganography()
    elif st.session_state.current_page == "File Encryption":
        page_file_encryption()

if __name__ == "__main__":
    main()