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


def derive_chacha_key(user_key):
    """Derive 32-byte key from user input using SHA256"""
    return hashlib.sha256(user_key.encode()).digest()

def encrypt_chacha20(text, user_key):
    """Encrypt text using ChaCha20 algorithm with user key"""
    try:
        # Derive key from user input
        key = derive_chacha_key(user_key)
        
        # Generate random nonce (16 bytes for ChaCha20)
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

def decrypt_chacha20(encrypted_text, user_key):
    """Decrypt text using ChaCha20 algorithm with user key - always return result even if wrong key"""
    try:
        if not encrypted_text:
            return "[EMPTY]"
            
        # Derive key from user input
        key = derive_chacha_key(user_key)
        
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

def create_car(model, brand, price, encryption_key):
    """Add new car to database with ChaCha20 encryption using user key"""
    try:
        # Pastikan semua data adalah string sebelum dienkripsi
        model_str = str(model)
        brand_str = str(brand)
        price_str = str(price)
        
        # Encrypt all fields dengan kunci user
        encrypted_model = encrypt_chacha20(model_str, encryption_key)
        encrypted_brand = encrypt_chacha20(brand_str, encryption_key)
        encrypted_price = encrypt_chacha20(price_str, encryption_key)

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
    """Get all cars from database with ChaCha20 decryption - always show results even with wrong key"""
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
            
            model = decrypt_chacha20(encrypted_model, encryption_key)
            brand = decrypt_chacha20(encrypted_brand, encryption_key)
            price = decrypt_chacha20(encrypted_price, encryption_key)
            
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

# ===== PAGE =====
def page_car_database():
    st.header("🚗 Database Mobil dengan Enkripsi ChaCha20") 
    
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
                            
                            enc_brand = encrypt_chacha20(brand, encryption_key)
                            enc_model = encrypt_chacha20(model, encryption_key)
                            enc_price = encrypt_chacha20(str(price), encryption_key)
                            
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
