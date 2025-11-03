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
from Halaman.super_enkripsi import page_super_encryption
from Halaman.enkripsi_file import page_file_encryption
from Halaman.stegano import page_steganography
from Halaman.enkripsi_database import page_car_database
# ===== FUNGSI CHACHA20 =====

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