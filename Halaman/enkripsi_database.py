import streamlit as st
import sqlite3
import hashlib
import base64
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

# Algoritma ChaCha20
def derive_chacha_key(user_key):
    return hashlib.sha256(user_key.encode()).digest()

def encrypt_chacha20(text, user_key):
    try:
        # Kunci dari input user
        key = derive_chacha_key(user_key)
        
        # Generate random nonce (12 bytes)
        nonce = get_random_bytes(12)
        
        # Ubah text to bytes
        text_bytes = text.encode('utf-8')
        
        # Membuat ChaCha20 cipher
        cipher = ChaCha20.new(key=key, nonce=nonce)
        
        # Enkripsi Teks
        ciphertext = cipher.encrypt(text_bytes)
        
        # Gabungkan nonce + ciphertext dan enkode as base64
        encrypted_data = nonce + ciphertext
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    except Exception as e:
        st.error(f"Encryption error: {e}")
        return None

def decrypt_chacha20(encrypted_text, user_key):
    try:
        if not encrypted_text:
            return "[EMPTY]"
            
        # Kunci dari input user
        key = derive_chacha_key(user_key)
        
        # Dekode from base64
        try:
            encrypted_data = base64.b64decode(encrypted_text.encode('utf-8'))
        except Exception:
            # Menambahkan Padding
            try:
                padding = 4 - (len(encrypted_text) % 4)
                if padding != 4:
                    encrypted_text += "=" * padding
                encrypted_data = base64.b64decode(encrypted_text.encode('utf-8'))
            except Exception as e:
                return f"[BASE64_ERROR: {str(e)}]"
        
        # Ekstrak nonce (first 12 bytes) dan ciphertext
        if len(encrypted_data) < 12:
            return f"[DATA_TOO_SHORT: {len(encrypted_data)} bytes]"
            
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        # Membuat ChaCha20 cipher
        cipher = ChaCha20.new(key=key, nonce=nonce)
        
        # Dekripsi Teks
        decrypted_bytes = cipher.decrypt(ciphertext)
        
        # Decode dengan UTF-8
        try:
            result = decrypted_bytes.decode('utf-8')
            # Periksa apakah hasilnya mengandung karakter yang tidak biasa yang mungkin menunjukkan kunci yang salah
            if any(ord(c) > 127 for c in result) and len(result) > 0:
                return f"[POSSIBLE_WRONG_KEY: {result}]"
            return result
        except UnicodeDecodeError:
            # Kembalikan byte mentah sebagai string untuk kunci yang salah
            return f"[DECODE_ERROR: {decrypted_bytes.hex()[:50]}...]"
    
    except Exception as e:
        return f"[DECRYPTION_ERROR: {str(e)}]"

def init_car_db():
    """Initialize database tabel cars"""
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS cars (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model TEXT NOT NULL,
            brand TEXT NOT NULL,
            price TEXT NOT NULL,
            dekripsi_mobil TEXT  -- KOLOM BARU
        )
    ''')
    conn.commit()
    conn.close()

def create_car(model, brand, price, encryption_key):
    try:
        # Pastikan semua data adalah string sebelum dienkripsi
        model_str = str(model)
        brand_str = str(brand)
        price_str = str(price)
        
        # Proses Enkripsi
        encrypted_model = encrypt_chacha20(model_str, encryption_key)
        encrypted_brand = encrypt_chacha20(brand_str, encryption_key)
        encrypted_price = encrypt_chacha20(price_str, encryption_key)
        encrypted_dekripsi = encrypt_chacha20("", encryption_key)

        if not all([encrypted_model, encrypted_brand, encrypted_price]):
            st.error("Gagal mengenkripsi data! Periksa kunci dan data input.")
            return False
            
        # Proses Database
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('INSERT INTO cars (model, brand, price, dekripsi_mobil) VALUES (?, ?, ?, ?)', 
                 (encrypted_model, encrypted_brand, encrypted_price, encrypted_dekripsi))
        conn.commit()
        new_id = c.lastrowid
        st.session_state['last_inserted_id'] = new_id
        conn.close()
        return True
    except Exception as e:
        st.error(f"Error: {e}")
        return False

def read_cars(encryption_key):
    try:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT * FROM cars')
        encrypted_cars = c.fetchall()
        conn.close()
        
        successful_decrypts = 0
        total_cars = len(encrypted_cars)
        
        # Dekrip Semua Data dengan kunci user
        decrypted_cars = []
        for car in encrypted_cars:
            car_id, encrypted_model, encrypted_brand, encrypted_price, encrypted_dekripsi = car
            
            model = decrypt_chacha20(encrypted_model, encryption_key)
            brand = decrypt_chacha20(encrypted_brand, encryption_key)
            price = decrypt_chacha20(encrypted_price, encryption_key)
            dekripsi_mobil = decrypt_chacha20(encrypted_dekripsi, encryption_key)
            
            # Kolom yang salah
            has_errors = any(field.startswith('[') and field.endswith(']') for field in [model, brand, price, dekripsi_mobil])
            
            if not has_errors:
                successful_decrypts += 1
                try:
                    price_float = float(price)
                    decrypted_cars.append((car_id, model, brand, price_float, dekripsi_mobil, True))
                except ValueError:
                    decrypted_cars.append((car_id, model, brand, price, dekripsi_mobil, True))
            else:
                decrypted_cars.append((car_id, model, brand, price, dekripsi_mobil, False))
                
        return decrypted_cars, successful_decrypts, total_cars
        
    except Exception as e:
        st.error(f"Error membaca data mobil: {e}")
        return [], 0, 0
    
def update_car_dekripsi(car_data, dekripsi_text, encryption_key):
    conn = None
    try:
        # Enkripsi deskripsi mobil
        encrypted_dekripsi = encrypt_chacha20(dekripsi_text, encryption_key)

        # Konversi ke base64 agar aman disimpan di kolom TEXT
        if isinstance(encrypted_dekripsi, (bytes, bytearray)):
            encrypted_b64 = base64.b64encode(encrypted_dekripsi).decode('utf-8')
        else:
            encrypted_b64 = str(encrypted_dekripsi)

        conn = sqlite3.connect('database.db', timeout=10)
        c = conn.cursor()

        # 1) Jika ada id, gunakan id
        if 'id' in car_data and car_data['id'] is not None:
            c.execute('UPDATE cars SET dekripsi_mobil = ? WHERE id = ?', (encrypted_b64, car_data['id']))
            conn.commit()
            return c.rowcount > 0

        # 2) Jika tidak ada id, cari berdasarkan plaintext
        c.execute('SELECT id FROM cars WHERE brand = ? AND model = ? AND price = ?', (
            car_data.get('brand'),
            car_data.get('model'),
            car_data.get('price')
        ))
        row = c.fetchone()
        if not row:
            return False

        car_id = row[0]
        c.execute('UPDATE cars SET dekripsi_mobil = ? WHERE id = ?', (encrypted_b64, car_id))
        conn.commit()
        return c.rowcount > 0

    except Exception as e:
        st.error(f"Error update deskripsi: {e}")
        return False

    finally:
        if conn:
            conn.close()
        
def delete_car(car_id):
    try:
        conn = sqlite3.connect('database.db')
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
    
    # Inisialisasi car database
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
        if show_encrypted:
            display_encrypted_data()
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
                        new_id = st.session_state.pop('last_inserted_id', None)
                        # AUTO REDIRECT KE SUPER ENCRYPTION
                        st.session_state.current_page = "Super Encryption"
                        st.session_state.new_car_data = {
                            'id': new_id,
                            'brand': brand,
                            'model': model, 
                            'price': price,
                            'encryption_key': encryption_key
                        }
                        st.rerun()
                    else:
                        st.error("❌ Gagal menambahkan mobil!")
    
    with tab2:
        st.subheader("Daftar Mobil (Hasil Dekripsi)")
        
        cars, successful_decrypts, total_cars = read_cars(encryption_key)
        
        if total_cars > 0:
            if successful_decrypts == total_cars:
                st.success(f"✅ Semua {total_cars} mobil berhasil didekripsi dengan kunci ini!")
            elif successful_decrypts > 0:
                st.warning(f"⚠️ {successful_decrypts} dari {total_cars} mobil berhasil didekripsi.")
            else:
                st.error(f" Tidak ada data yang berhasil didekripsi dengan kunci ini.")
        
        if not cars:
            st.info("📝 Belum ada data mobil.")
        else:
            st.write(f"**Menampilkan {len(cars)} mobil:**")
            
            for car in cars:
                car_id, model, brand, price, dekripsi_mobil, decrypt_success = car
                
                with st.container():
                    if decrypt_success:
                        st.markdown(f'<div style="border-left: 4px solid #00ff00; padding-left: 10px;">', unsafe_allow_html=True)
                    else:
                        st.markdown(f'<div style="border-left: 4px solid #ff0000; padding-left: 10px;">', unsafe_allow_html=True)
                    
                    col1, col2, col3, col4 = st.columns([2, 2, 2, 1])
                    
                    with col1:
                        if decrypt_success:
                            st.write(f"**Brand:{brand} \t Model:{model}**")
                        else:
                            st.write(f"~~Brand:{brand} \t Model:{model}~~")
                        st.caption(f"ID: {car_id}")
                    
                    with col2:
                        if isinstance(price, (int, float)):
                            st.write(f"**Harga:** Rp {price:,.0f}")
                        else:
                            st.write(f"**Harga:** {price}")
                    
                    with col3:
                        st.write("**Dekripsi Mobil:**")
                    if dekripsi_mobil and dekripsi_mobil != "[EMPTY]":
                        with st.expander("📋 Lihat Deskripsi Lengkap"):
                            st.text_area(
                                "Salin teks ini untuk didekripsi:",
                                value=dekripsi_mobil,
                                key=f"desc_{car_id}",
                                height=150,
                                label_visibility="collapsed"
                            )
                    else:
                        st.info("Belum diisi")
                    
                    with col4:
                        if st.button(f"🗑️", key=f"delete_{car_id}"):
                            if delete_car(car_id) and decrypt_success:
                                st.success("✅ Data dihapus!")
                                st.rerun()
                            else:
                                st.error("❌ Gagal Menghapus data")
                    
                    st.markdown('</div>', unsafe_allow_html=True)
                    st.divider()
            # Tampilkan data terenkripsi saja jika checkbox dicentang
def display_encrypted_data():
    # Tampilkan encrypted data dari database
    st.subheader("🔐 Data Terenkripsi di Database")
    
    try:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT * FROM cars')
        encrypted_cars = c.fetchall()
        conn.close()
        
        if not encrypted_cars:
            st.info("Tidak ada data terenkripsi di database.")
            return
            
        for car in encrypted_cars:
            car_id, encrypted_model, encrypted_brand, encrypted_price, car_decription = car
            
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
                st.write("**Deskripsi:**")
                st.code(car_decription)
                st.write(f"Panjang: {len(car_decription)} karakter")

                st.write("**Harga:**")
                st.code(encrypted_price)
                st.write(f"Panjang: {len(encrypted_price)} karakter")


                
    except Exception as e:
        st.error(f"Error mengambil data terenkripsi: {e}")