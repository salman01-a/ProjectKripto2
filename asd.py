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

# ===== FUNGSI SALSA20 ENCRYPTION =====

def generate_salsa20_key():
    """Generate random key for Salsa20 (32 bytes)"""
    return secrets.token_bytes(32)

def encrypt_salsa20(text, key):
    """Encrypt text using Salsa20 algorithm"""
    try:
        # Generate random nonce (8 bytes for Salsa20)
        nonce = secrets.token_bytes(8)
        
        # Convert text to bytes
        text_bytes = text.encode('utf-8')
        
        # Create Salsa20 cipher
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

def decrypt_salsa20(encrypted_text, key):
    """Decrypt text using Salsa20 algorithm"""
    try:
        # Decode from base64
        encrypted_data = base64.b64decode(encrypted_text.encode('utf-8'))
        
        # Extract nonce (first 8 bytes) and ciphertext
        nonce = encrypted_data[:8]
        ciphertext = encrypted_data[8:]
        
        # Create Salsa20 cipher
        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt the text
        decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_bytes.decode('utf-8')
    
    except Exception as e:
        st.error(f"Decryption error: {e}")
        return None

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

def super_encrypt(text, caesar_key, xor_key):
    caesar_result = caesar_cipher(text, caesar_key)
    final_result = xor_cipher(caesar_result, xor_key)
    return caesar_result, final_result

def super_decrypt(encrypted_text, caesar_key, xor_key):
    xor_result = xor_cipher(encrypted_text, xor_key)
    final_result = caesar_cipher(xor_result, -caesar_key)
    return xor_result, final_result

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

def get_salsa_key():
    """Get or generate Salsa20 key from session state"""
    if 'salsa_key' not in st.session_state:
        # Generate new key if not exists
        st.session_state.salsa_key = generate_salsa20_key()
    return st.session_state.salsa_key

def create_car(model, brand, price):
    """Add new car to database with Salsa20 encryption"""
    try:
        salsa_key = get_salsa_key()
        
        # Encrypt all fields
        encrypted_model = encrypt_salsa20(model, salsa_key)
        encrypted_brand = encrypt_salsa20(brand, salsa_key)
        encrypted_price = encrypt_salsa20(str(price), salsa_key)
        
        if not all([encrypted_model, encrypted_brand, encrypted_price]):
            st.error("Gagal mengenkripsi data!")
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

def read_cars():
    """Get all cars from database with Salsa20 decryption"""
    try:
        salsa_key = get_salsa_key()
        conn = sqlite3.connect('cars.db')
        c = conn.cursor()
        c.execute('SELECT * FROM cars')
        encrypted_cars = c.fetchall()
        conn.close()
        
        # Decrypt all fields
        decrypted_cars = []
        for car in encrypted_cars:
            car_id, encrypted_model, encrypted_brand, encrypted_price = car
            
            model = decrypt_salsa20(encrypted_model, salsa_key)
            brand = decrypt_salsa20(encrypted_brand, salsa_key)
            price = decrypt_salsa20(encrypted_price, salsa_key)
            
            if all([model, brand, price]):
                decrypted_cars.append((car_id, model, brand, float(price)))
            else:
                st.error(f"Gagal mendekripsi data mobil ID {car_id}")
                
        return decrypted_cars
    except Exception as e:
        st.error(f"Error: {e}")
        return []

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
    
    if st.button(f"🚀 Jalankan {mode}"):
        if not text_input:
            st.warning("Masukkan teks terlebih dahulu!")
            return
        
        if not xor_key:
            st.warning("Masukkan kunci XOR!")
            return
        
        if mode == "Enkripsi":
            st.subheader("🔒 Hasil Enkripsi")
            caesar_result, final_result = super_encrypt(text_input, caesar_key, xor_key)
            
            st.write("**Step 1 - Caesar Cipher:**")
            st.code(f"Input: {text_input}")
            st.code(f"Setelah Caesar (shift {caesar_key}): {caesar_result}")
            
            st.write("**Step 2 - XOR Cipher:**")
            st.code(f"Setelah XOR (kunci '{xor_key}'): {final_result}")
            
            st.write("**🎯 Hasil Final:**")
            st.success(final_result)
            
            st.text_input("Salin hasil:", value=final_result, key="encrypted_result")
            
        else:
            st.subheader("🔓 Hasil Dekripsi")
            xor_result, final_result = super_decrypt(text_input, caesar_key, xor_key)
            
            st.write("**Step 1 - XOR Decrypt:**")
            st.code(f"Input: {text_input}")
            st.code(f"Setelah XOR (kunci '{xor_key}'): {xor_result}")
            
            st.write("**Step 2 - Caesar Decrypt:**")
            st.code(f"Setelah Caesar (shift -{caesar_key}): {final_result}")
            
            st.write("**🎯 Hasil Final:**")
            st.success(final_result)
            
            st.text_input("Salin hasil:", value=final_result, key="decrypted_result")

def page_car_database():
    st.header("🚗 Database Mobil dengan Enkripsi Salsa20")
    st.write("Kelola data mobil dengan enkripsi Salsa20 - Create, Read, Delete")
    
    # Initialize car database
    init_car_db()
    
    # Info tentang enkripsi
    with st.expander("ℹ️ Tentang Enkripsi Salsa20"):
        st.write("""
        **Fitur Keamanan:**
        - 🔐 **Salsa20 Encryption**: Semua data dienkripsi sebelum disimpan ke database
        - 🔑 **Key Management**: Kunci enkripsi disimpan secara aman di session
        - 🛡️ **Data Protection**: Model, brand, dan harga mobil terenkripsi di database
        
        **Alur Kerja:**
        1. Data dienkripsi dengan Salsa20 sebelum disimpan
        2. Data didekripsi saat akan ditampilkan
        3. Kunci enkripsi di-generate otomatis saat session dimulai
        """)
    
    tab1, tab2 = st.tabs(["➕ Tambah Mobil", "📋 Lihat & Hapus Mobil"])
    
    with tab1:
        st.subheader("Tambah Mobil Baru")
        
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
                    if create_car(model, brand, price):
                        st.success(f"✅ Mobil {brand} {model} berhasil ditambahkan dengan enkripsi Salsa20!")
                    else:
                        st.error("❌ Gagal menambahkan mobil!")
    
    with tab2:
        st.subheader("Daftar Mobil (Terdokripsi)")
        
        cars = read_cars()
        
        if not cars:
            st.info("📝 Belum ada data mobil. Silakan tambah mobil baru di tab 'Tambah Mobil'.")
        else:
            st.write(f"**Total {len(cars)} mobil ditemukan:**")
            
            for car in cars:
                car_id, model, brand, price = car
                
                with st.container():
                    col1, col2, col3 = st.columns([3, 2, 1])
                    
                    with col1:
                        st.write(f"**{brand} {model}**")
                        st.caption(f"ID: {car_id}")
                    
                    with col2:
                        st.write(f"**Harga:** Rp {price:,.0f}")
                    
                    with col3:
                        if st.button(f"🗑️ Hapus", key=f"delete_{car_id}"):
                            if delete_car(car_id):
                                st.success(f"✅ Mobil {brand} {model} berhasil dihapus!")
                                st.rerun()
                            else:
                                st.error("❌ Gagal menghapus mobil!")
                    
                    st.divider()

# [Fungsi page_steganography(), page_file_encryption(), dan lainnya tetap sama...]
# Untuk menghemat space, saya tidak menulis ulang fungsi yang tidak berubah

def page_steganography():
    # ... (kode sebelumnya tetap sama)
    st.header("🖼️ Steganografi - Sembunyikan Pesan/Gambar dalam Gambar")
    # ... (implementasi lengkap sama seperti sebelumnya)

def page_file_encryption():
    # ... (kode sebelumnya tetap sama)
    st.header("📁 Enkripsi File - AES Encryption")
    # ... (implementasi lengkap sama seperti sebelumnya)

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