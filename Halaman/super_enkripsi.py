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
