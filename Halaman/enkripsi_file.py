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
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from typing import Tuple
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
import secrets

def encrypt_file(file_bytes: bytes, password: str) -> Tuple[bytes, bytes]:
    """Enkripsi file menggunakan AES-128-CBC.
    Mengambil 16 byte pertama dari SHA-256(password) sebagai kunci 128-bit.
    Mengembalikan (encrypted_bytes, iv)."""
    try:
        # derive 16-byte key (AES-128) dari password
        key_bytes = hashlib.sha256(password.encode()).digest()[:16]  # 16 bytes = 128 bit
        iv = get_random_bytes(AES.block_size)  # AES.block_size == 16

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(file_bytes, AES.block_size))
        return encrypted, iv
    except Exception as e:
        raise Exception(f"Encryption failed: {str(e)}")

def decrypt_file(encrypted_bytes: bytes, iv: bytes, password: str) -> bytes:
    """Dekripsi file AES-128-CBC (sesuai fungsi encrypt_file di atas)."""
    try:
        key_bytes = hashlib.sha256(password.encode()).digest()[:16]
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
        return decrypted
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")

def encrypt_file_to_pdf(file_bytes: bytes, password: str, original_filename: str) -> bytes:
    """Enkripsi file dan hasilkan PDF dengan data terenkripsi"""
    try:
        # Enkripsi file
        encrypted_data, iv = encrypt_file(file_bytes, password)
        
        # Buat PDF dengan reportlab
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        
        # Header PDF
        c.setFont("Helvetica-Bold", 16)
        c.drawString(100, 750, "🔐 FILE TERENKRIPSI - SUPER ENCRYPTION APP")
        c.setFont("Helvetica", 10)
        c.drawString(100, 730, f"File Asli: {original_filename}")
        c.drawString(100, 715, f"Waktu Enkripsi: {st.session_state.get('encryption_time', 'Unknown')}")
        c.drawString(100, 700, f"Ukuran File: {len(file_bytes)} bytes")
        
        # Data terenkripsi (dalam format base64 untuk kemudahan)
        encrypted_b64 = base64.b64encode(iv + encrypted_data).decode('utf-8')
        
        # Tambahkan data terenkripsi ke PDF (dipotong jika terlalu panjang)
        c.drawString(100, 680, "Data Terenkripsi (Base64):")
        y_position = 660
        chunk_size = 80  # Karakter per baris
        
        for i in range(0, min(len(encrypted_b64), 2000), chunk_size):
            if y_position < 100:  # Buat halaman baru jika perlu
                c.showPage()
                y_position = 750
                c.setFont("Helvetica", 8)
            
            chunk = encrypted_b64[i:i+chunk_size]
            c.drawString(100, y_position, chunk)
            y_position -= 15
        
        # Informasi keamanan
        c.showPage()
        c.setFont("Helvetica-Bold", 14)
        c.drawString(100, 750, "INFORMASI KEAMANAN")
        c.setFont("Helvetica", 10)
        security_info = [
            "File ini telah dienkripsi menggunakan algoritma AES-128-CBC",
            "Password diperlukan untuk mendekripsi file",
            "Simpan password dengan aman! File tidak dapat dipulihkan tanpa password",
            "Untuk dekripsi, gunakan aplikasi Super Encryption dengan password yang sama",
            f"SHA256 Hash: {hashlib.sha256(file_bytes).hexdigest()[:32]}..."
        ]
        
        y_pos = 720
        for info in security_info:
            c.drawString(100, y_pos, info)
            y_pos -= 20
        
        c.save()
        buffer.seek(0)
        return buffer.getvalue()
        
    except Exception as e:
        raise Exception(f"PDF creation failed: {str(e)}")

def decrypt_pdf_to_file(pdf_bytes: bytes, password: str) -> Tuple[bytes, str]:
    """Dekripsi PDF yang berisi data terenkripsi"""
    try:
        # Ekstrak data dari PDF (sederhana - asumsi format tertentu)
        # Dalam implementasi nyata, Anda mungkin perlu parsing PDF yang lebih canggih
        pdf_text = pdf_bytes.decode('latin-1', errors='ignore')
        
        # Cari data base64 dalam PDF
        import re
        base64_pattern = r'[A-Za-z0-9+/]{40,}={0,2}'
        base64_matches = re.findall(base64_pattern, pdf_text)
        
        if not base64_matches:
            raise Exception("Tidak dapat menemukan data terenkripsi dalam PDF")
        
        # Gabungkan semua potongan base64 (ambil yang terpanjang sebagai data utama)
        encrypted_b64 = max(base64_matches, key=len)
        
        # Decode base64
        encrypted_data_with_iv = base64.b64decode(encrypted_b64)
        
        # Pisahkan IV (16 byte pertama) dan data terenkripsi
        iv = encrypted_data_with_iv[:16]
        encrypted_data = encrypted_data_with_iv[16:]
        
        # Dekripsi
        decrypted_data = decrypt_file(encrypted_data, iv, password)
        
        # Cari nama file asli dari PDF
        filename_match = re.search(r'File Asli: ([^\n]+)', pdf_text)
        original_filename = filename_match.group(1) if filename_match else "decrypted_file"
        
        return decrypted_data, original_filename
        
    except Exception as e:
        raise Exception(f"PDF decryption failed: {str(e)}")

def page_file_encryption():
    st.header("📁 Enkripsi File - AES Encryption")
    st.write("Enkripsi file dengan algoritma AES yang aman menggunakan password - **Hasil selalu dalam format PDF**")
    
    tab1, tab2 = st.tabs(["🔒 Enkripsi File ke PDF", "🔓 Dekripsi PDF ke File"])
    
    with tab1:
        st.subheader("Enkripsi File ke PDF")
        
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
            
            if st.button("🔐 Enkripsi File ke PDF", type="primary"):
                if not encrypt_password:
                    st.error("❌ Masukkan password untuk enkripsi!")
                    return
                
                if encrypt_password != confirm_password:
                    st.error("❌ Password dan konfirmasi password tidak cocok!")
                    return
                
                if len(encrypt_password) < 4:
                    st.error("❌ Password harus minimal 4 karakter!")
                    return
                
                try:
                    # Simpan waktu enkripsi
                    from datetime import datetime
                    st.session_state.encryption_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    # Baca file data
                    file_data = file_to_encrypt.getvalue()
                    
                    # Enkripsi file dan buat PDF
                    with st.spinner("🔄 Sedang mengenkripsi file dan membuat PDF..."):
                        pdf_data = encrypt_file_to_pdf(file_data, encrypt_password, file_to_encrypt.name)
                    
                    st.success("✅ File berhasil dienkripsi dan dikonversi ke PDF!")
                    
                    # Download file PDF terenkripsi
                    original_name = file_to_encrypt.name
                    pdf_filename = f"encrypted_{os.path.splitext(original_name)[0]}.pdf"
                    
                    st.download_button(
                        label="📥 Download File PDF Terenkripsi",
                        data=pdf_data,
                        file_name=pdf_filename,
                        mime="application/pdf"
                    )
                    
                    # Info keamanan
                    st.info("""
                    **💡 Informasi:**
                    - File hasil enkripsi disimpan dalam format PDF
                    - Data terenkripsi disimpan sebagai teks dalam PDF
                    - Simpan password dengan aman! File tidak bisa didekripsi tanpa password
                    - File asli telah diamankan dengan algoritma AES-128-CBC
                    """)
                    
                except Exception as e:
                    st.error(f"❌ Gagal mengenkripsi file: {str(e)}")
    
    with tab2:
        st.subheader("Dekripsi PDF ke File Asli")
        
        # Upload file PDF terenkripsi
        encrypted_pdf = st.file_uploader("Pilih file PDF terenkripsi:", 
                                        type=['pdf'],
                                        key="decrypt_upload")
        
        if encrypted_pdf is not None:
            st.write(f"**File PDF:** {encrypted_pdf.name}")
            
            # Input password untuk dekripsi
            decrypt_password = st.text_input("Password untuk dekripsi:", type="password", key="decrypt_pass")
            
            if st.button("🔓 Dekripsi PDF", type="primary"):
                if not decrypt_password:
                    st.error("❌ Masukkan password untuk dekripsi!")
                    return
                
                try:
                    # Baca file PDF
                    pdf_data = encrypted_pdf.getvalue()
                    
                    # Dekripsi PDF
                    with st.spinner("🔄 Sedang mendekripsi PDF..."):
                        decrypted_data, original_filename = decrypt_pdf_to_file(pdf_data, decrypt_password)
                    
                    st.success("✅ PDF berhasil didekripsi!")
                    
                    # Tentukan MIME type berdasarkan ekstensi
                    file_extension = os.path.splitext(original_filename)[1].lower()
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
                        file_name=original_filename,
                        mime=mime_type
                    )
                    
                    # Tampilkan info
                    st.info(f"**File asli berhasil dipulihkan:** {original_filename}")
                    
                except Exception as e:
                    st.error(f"❌ Gagal mendekripsi PDF: {str(e)}")
                    st.error("Kemungkinan password salah atau file PDF bukan file terenkripsi yang valid!")
    
    st.write("---")
    st.subheader("ℹ️ Tentang Sistem Enkripsi File PDF")
    st.write("""
    **Fitur Utama:**
    - 🔒 **Enkripsi AES-128-CBC** - Standar keamanan tinggi
    - 📄 **Hasil selalu PDF** - Format seragam untuk semua file
    - 🔑 **Password-based** - Aman dan mudah digunakan
    - 📋 **Metadata lengkap** - Informasi enkripsi tercatat dalam PDF
    
    **Alur Kerja:**
    1. Upload file apa saja (txt, pdf, docx, jpg, dll)
    2. File dienkripsi dengan AES-128-CBC
    3. Data terenkripsi + metadata disimpan dalam PDF
    4. Download file PDF terenkripsi
    5. Untuk dekripsi: upload file PDF terenkripsi
    6. PDF didekripsi ke format asli dengan password yang benar
    """)
