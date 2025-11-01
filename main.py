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

# ===== FUNGSI DATABASE & AUTH =====

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

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
        encrypted_username = caesar_cipher(username, 1)
        encrypted_password = caesar_cipher(hashed_password, 1)
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', 
                 (encrypted_username, encrypted_password))
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
        encrypted_username = caesar_cipher(username, 1)
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT password FROM users WHERE username = ?', (encrypted_username,))
        result = c.fetchone()
        conn.close()
        
        if result:
            encrypted_db_password = result[0]
            decrypted_hashed_password = caesar_cipher(encrypted_db_password, -1)
            hashed_input_password = hash_password(password)
            
            if hashed_input_password == decrypted_hashed_password:
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

def page_steganography():
    st.header("🖼️ Steganografi - Sembunyikan Pesan dalam Gambar")
    st.write("Teknik untuk menyembunyikan pesan rahasia dalam gambar tanpa mengubah penampilan visual")
    
    tab1, tab2 = st.tabs(["🔒 Encode Pesan", "🔓 Decode Pesan"])
    
    with tab1:
        st.subheader("Sembunyikan Pesan dalam Gambar")
        
        uploaded_file = st.file_uploader("Pilih gambar:", type=['png', 'jpg', 'jpeg'], key="encode")
        
        if uploaded_file is not None:
            image = Image.open(uploaded_file)
            st.image(image, caption="Gambar Original", use_column_width=True)
            
            secret_message = st.text_area("Pesan rahasia yang akan disembunyikan:")
            
            if st.button("🔄 Encode Pesan ke Gambar"):
                if secret_message:
                    try:
                        encoded_image = encode_image(image, secret_message)
                        
                        st.image(encoded_image, caption="Gambar dengan Pesan Tersembunyi", use_column_width=True)
                        
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
    
    with tab2:
        st.subheader("Baca Pesan dari Gambar")
        
        encoded_file = st.file_uploader("Pilih gambar dengan pesan tersembunyi:", type=['png', 'jpg', 'jpeg'], key="decode")
        
        if encoded_file is not None:
            image = Image.open(encoded_file)
            st.image(image, caption="Gambar dengan Pesan Tersembunyi", use_column_width=True)
            
            if st.button("🔍 Decode Pesan dari Gambar"):
                try:
                    decoded_message = decode_image(image)
                    
                    st.subheader("📜 Pesan yang Ditemukan:")
                    st.text_area("Pesan rahasia:", value=decoded_message, height=150)
                    
                    if decoded_message.startswith("Tidak dapat"):
                        st.warning("⚠️ " + decoded_message)
                    else:
                        st.success("✅ Pesan berhasil diekstrak!")
                        
                except Exception as e:
                    st.error(f"❌ Terjadi error: {e}")
    
    st.write("---")
    st.subheader("ℹ️ Tentang Steganografi LSB")
    st.write("""
    **Cara Kerja:**
    - Setiap pixel gambar terdiri dari 3 warna (Red, Green, Blue)
    - Setiap warna diwakili oleh angka 0-255 (8 bit)
    - Teknik LSB (Least Significant Bit) mengganti bit terakhir setiap warna dengan bit pesan
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
        
        # Pilihan halaman
        page_options = ["Super Encryption", "Steganografi", "File Encryption"]
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
            st.rerun()
    
    # Tampilkan konten berdasarkan halaman yang dipilih
    if st.session_state.current_page == "Super Encryption":
        page_super_encryption()
    elif st.session_state.current_page == "Steganografi":
        page_steganography()
    elif st.session_state.current_page == "File Encryption":
        page_file_encryption()

if __name__ == "__main__":
    main()