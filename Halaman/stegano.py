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
