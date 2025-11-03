import streamlit as st
import numpy as np
from PIL import Image
import io

import numpy as np
from PIL import Image

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

def calculate_complexity(block):
    """Calculate complexity of an image block using variance"""
    return np.var(block)

def get_adaptive_bits(complexity, thresholds=(10, 50)):
    """Determine number of LSB bits to use based on complexity"""
    low_thresh, high_thresh = thresholds
    
    if complexity < low_thresh:
        return 1  # Smooth area - use only 1 LSB
    elif complexity < high_thresh:
        return 2  # Medium complexity - use 2 LSBs
    else:
        return 3  # Complex area - use 3 LSBs

def encode_image_adaptive_lsb(image, message, block_size=8):
    """Encode message into image using Adaptive LSB steganography"""
    img_array = np.array(image)
    binary_message = text_to_binary(message) + '1111111111111110'  # Delimiter
    
    height, width = img_array.shape[:2]
    
    # Calculate maximum capacity
    max_bits = 0
    for y in range(0, height, block_size):
        for x in range(0, width, block_size):
            block = img_array[y:y+block_size, x:x+block_size]
            if block.size > 0:
                complexity = calculate_complexity(block)
                bits_per_pixel = get_adaptive_bits(complexity)
                max_bits += block.size * bits_per_pixel
    
    if len(binary_message) > max_bits:
        raise ValueError(f"Pesan terlalu panjang! Maksimal {max_bits//8} karakter untuk gambar ini.")
    
    message_index = 0
    encoded_array = img_array.copy()
    
    for y in range(0, height, block_size):
        for x in range(0, width, block_size):
            block = encoded_array[y:y+block_size, x:x+block_size]
            if block.size == 0 or message_index >= len(binary_message):
                continue
                
            complexity = calculate_complexity(block)
            bits_to_use = get_adaptive_bits(complexity)
            
            # Flatten the block for processing
            flat_block = block.reshape(-1)
            
            for i in range(len(flat_block)):
                if message_index >= len(binary_message):
                    break
                    
                pixel = flat_block[i]
                bits_available = min(bits_to_use, len(binary_message) - message_index)
                
                # Clear the LSB bits and set them to our message bits
                mask = (0xFF << bits_available) & 0xFF  # Create mask to clear LSBs
                new_pixel = (pixel & mask) | int(binary_message[message_index:message_index+bits_available], 2)
                flat_block[i] = new_pixel
                message_index += bits_available
    
    return Image.fromarray(encoded_array.astype('uint8'))

def decode_image_adaptive_lsb(image, block_size=8):
    """Decode message from image using Adaptive LSB steganography"""
    img_array = np.array(image)
    height, width = img_array.shape[:2]
    
    binary_message = ''
    message_complete = False
    
    for y in range(0, height, block_size):
        for x in range(0, width, block_size):
            if message_complete:
                break
                
            block = img_array[y:y+block_size, x:x+block_size]
            if block.size == 0:
                continue
                
            complexity = calculate_complexity(block)
            bits_to_use = get_adaptive_bits(complexity)
            
            # Flatten the block for processing
            flat_block = block.reshape(-1)
            
            for pixel in flat_block:
                if message_complete:
                    break
                    
                # Extract the LSB bits
                bits = pixel & ((1 << bits_to_use) - 1)
                binary_bits = format(bits, f'0{bits_to_use}b')
                binary_message += binary_bits
                
                # Check for delimiter
                if '1111111111111110' in binary_message:
                    message_complete = True
                    end_index = binary_message.find('1111111111111110')
                    binary_message = binary_message[:end_index]
                    break
    
    try:
        # Try to decode with standard 8-bit chunks
        message = binary_to_text(binary_message)
        return message
    except:
        try:
            # If standard decoding fails, try to handle variable bit lengths
            message = ''
            i = 0
            while i + 8 <= len(binary_message):
                byte = binary_message[i:i+8]
                message += chr(int(byte, 2))
                i += 8
            return message
        except:
            return "Tidak dapat mendekode pesan. Mungkin gambar tidak mengandung pesan tersembunyi."

def encode_image_in_image_adaptive_lsb(host_image: Image.Image, secret_image: Image.Image, block_size=8) -> Image.Image:
    """Encode secret image into host image using Adaptive LSB"""
    if not isinstance(host_image, Image.Image) or not isinstance(secret_image, Image.Image):
        raise ValueError("Input harus berupa objek PIL Image")
        
    host_image = host_image.convert('RGB')
    secret_image = secret_image.convert('RGB')
    
    host_arr = np.array(host_image, dtype=np.uint8)
    secret_arr = np.array(secret_image, dtype=np.uint8)
    
    # Calculate available capacity
    height, width = host_arr.shape[:2]
    max_bits = 0
    for y in range(0, height, block_size):
        for x in range(0, width, block_size):
            block = host_arr[y:y+block_size, x:x+block_size]
            if block.size > 0:
                complexity = calculate_complexity(block)
                bits_per_pixel = get_adaptive_bits(complexity)
                max_bits += block.size * bits_per_pixel
    
    # Resize secret image to fit in available capacity
    secret_bits_needed = secret_arr.size * 8 + 32  # 32 bits for dimensions
    if secret_bits_needed > max_bits:
        # Calculate resize factor
        resize_factor = (max_bits - 32) / (secret_arr.size * 8)
        new_size = (int(secret_arr.shape[1] * resize_factor**0.5), 
                   int(secret_arr.shape[0] * resize_factor**0.5))
        secret_img = secret_image.resize(new_size)
        secret_arr = np.array(secret_img, dtype=np.uint8)
    
    # Store original dimensions
    width, height = secret_arr.shape[1], secret_arr.shape[0]
    dimension_bits = format(width, '016b') + format(height, '016b')
    
    # Convert secret image to binary string
    binary_secret = dimension_bits + ''.join([format(pixel, '08b') for pixel in secret_arr.flatten()])
    
    # Encode using adaptive LSB
    message_index = 0
    encoded_array = host_arr.copy()
    
    for y in range(0, height, block_size):
        for x in range(0, width, block_size):
            block = encoded_array[y:y+block_size, x:x+block_size]
            if block.size == 0 or message_index >= len(binary_secret):
                continue
                
            complexity = calculate_complexity(block)
            bits_to_use = get_adaptive_bits(complexity)
            
            flat_block = block.reshape(-1)
            
            for i in range(len(flat_block)):
                if message_index >= len(binary_secret):
                    break
                    
                pixel = flat_block[i]
                bits_available = min(bits_to_use, len(binary_secret) - message_index)
                
                mask = (0xFF << bits_available) & 0xFF
                new_pixel = (pixel & mask) | int(binary_secret[message_index:message_index+bits_available], 2)
                flat_block[i] = new_pixel
                message_index += bits_available
    
    return Image.fromarray(encoded_array)

def decode_image_from_image_adaptive_lsb(stego_image: Image.Image, block_size=8) -> Image.Image:
    """Decode secret image from host image using Adaptive LSB"""
    if not isinstance(stego_image, Image.Image):
        raise ValueError("Input harus berupa objek PIL Image")
        
    stego_image = stego_image.convert('RGB')
    stego_arr = np.array(stego_image)
    
    height, width = stego_arr.shape[:2]
    binary_data = ''
    data_complete = False
    
    # Extract binary data using adaptive LSB
    for y in range(0, height, block_size):
        for x in range(0, width, block_size):
            if data_complete:
                break
                
            block = stego_arr[y:y+block_size, x:x+block_size]
            if block.size == 0:
                continue
                
            complexity = calculate_complexity(block)
            bits_to_use = get_adaptive_bits(complexity)
            
            flat_block = block.reshape(-1)
            
            for pixel in flat_block:
                if data_complete:
                    break
                    
                bits = pixel & ((1 << bits_to_use) - 1)
                binary_bits = format(bits, f'0{bits_to_use}b')
                binary_data += binary_bits
                
                # Check if we have enough data for dimensions + some content
                if len(binary_data) >= 32 and len(binary_data) % 8 == 0:
                    try:
                        # Try to extract dimensions
                        width_bits = binary_data[:16]
                        height_bits = binary_data[16:32]
                        secret_width = int(width_bits, 2)
                        secret_height = int(height_bits, 2)
                        
                        total_bits_needed = 32 + (secret_width * secret_height * 3 * 8)
                        if len(binary_data) >= total_bits_needed:
                            data_complete = True
                    except:
                        continue
    
    if len(binary_data) < 32:
        raise ValueError("Tidak cukup data untuk mengekstrak dimensi gambar")
    
    # Extract dimensions
    width_bits = binary_data[:16]
    height_bits = binary_data[16:32]
    secret_width = int(width_bits, 2)
    secret_height = int(height_bits, 2)
    binary_pixels = binary_data[32:]
    
    # Convert binary to pixels
    secret_pixels = []
    for i in range(0, len(binary_pixels), 8):
        if i + 8 <= len(binary_pixels):
            pixel = int(binary_pixels[i:i+8], 2)
            secret_pixels.append(pixel)
    
    # Create array with correct dimensions
    try:
        secret_arr = np.array(secret_pixels[:secret_width*secret_height*3], dtype=np.uint8)
        secret_arr = secret_arr.reshape((secret_height, secret_width, 3))
        return Image.fromarray(secret_arr)
    except ValueError as e:
        raise ValueError(f"Gagal mengekstrak gambar: {str(e)}")
def page_steganography():
    st.header("🖼️ Steganografi Adaptive LSB - Sembunyikan Pesan/Gambar dalam Gambar")
    st.write("Teknik untuk menyembunyikan pesan rahasia atau gambar dalam gambar menggunakan **Adaptive LSB (Least Significant Bit)** yang cerdas")
    
    # ===== TAB DEFINITIONS =====
    tab1, tab2, tab3, tab4 = st.tabs([
        "🔒 Encode Pesan Adaptive LSB", 
        "🔓 Decode Pesan Adaptive LSB", 
        "🖼️ Encode Gambar Adaptive LSB", 
        "🔍 Decode Gambar Adaptive LSB"
    ])
    
    # ===== TAB 1: ENCODE TEKS ADAPTIVE LSB =====
    with tab1:
        st.subheader("Sembunyikan Pesan Teks dalam Gambar (Adaptive LSB)")
        st.info("✨ **Adaptive LSB**: Teknik cerdas yang menyesuaikan jumlah bit LSB berdasarkan kompleksitas gambar!")
        
        uploaded_file = st.file_uploader("Pilih gambar cover:", type=['png', 'jpg', 'jpeg'], key="encode_text_adaptive")
        
        if uploaded_file is not None:
            image = Image.open(uploaded_file)
            st.image(image, caption="Gambar Cover", use_container_width=True)
            
            secret_message = st.text_area("Pesan rahasia yang akan disembunyikan:", key="text_secret_adaptive")
            
            # Advanced options
            with st.expander("⚙️ Pengaturan Lanjutan"):
                block_size = st.slider("Ukuran Blok:", min_value=4, max_value=16, value=8, 
                                     help="Ukuran blok untuk analisis kompleksitas")
                low_thresh = st.slider("Threshold Rendah:", min_value=5, max_value=50, value=10,
                                     help="Kompleksitas rendah = 1 bit LSB")
                high_thresh = st.slider("Threshold Tinggi:", min_value=20, max_value=100, value=50,
                                      help="Kompleksitas tinggi = 3 bit LSB")
            
            if st.button("🔄 Encode Pesan ke Gambar (Adaptive LSB)", key="btn_encode_text_adaptive"):
                if secret_message:
                    try:
                        with st.spinner("Mengkodekan pesan dengan Adaptive LSB..."):
                            # Use custom thresholds
                            def get_custom_bits(complexity):
                                if complexity < low_thresh:
                                    return 1
                                elif complexity < high_thresh:
                                    return 2
                                else:
                                    return 3
                            
                            # Calculate capacity first
                            img_array = np.array(image)
                            height, width = img_array.shape[:2]
                            max_bits = 0
                            for y in range(0, height, block_size):
                                for x in range(0, width, block_size):
                                    block = img_array[y:y+block_size, x:x+block_size]
                                    if block.size > 0:
                                        complexity = calculate_complexity(block)
                                        bits_per_pixel = get_custom_bits(complexity)
                                        max_bits += block.size * bits_per_pixel
                            
                            st.info(f"📊 Kapasitas maksimal: {max_bits//8} karakter")
                            
                            encoded_image = encode_image_adaptive_lsb(image, secret_message, block_size)
                            
                            # Tampilkan perbandingan
                            col1, col2 = st.columns(2)
                            with col1:
                                st.image(image, caption="Gambar Asli", use_container_width=True)
                            with col2:
                                st.image(encoded_image, caption="Gambar dengan Adaptive LSB", use_container_width=True)
                            
                            # Calculate PSNR
                            original_array = np.array(image)
                            encoded_array = np.array(encoded_image)
                            mse = np.mean((original_array - encoded_array) ** 2)
                            if mse == 0:
                                psnr = 100
                            else:
                                psnr = 20 * np.log10(255.0 / np.sqrt(mse))
                            
                            st.metric("📈 Kualitas Gambar (PSNR)", f"{psnr:.2f} dB")
                            
                            buf = io.BytesIO()
                            encoded_image.save(buf, format='PNG')
                            st.download_button(
                                label="📥 Download Gambar dengan Pesan Tersembunyi (Adaptive LSB)",
                                data=buf.getvalue(),
                                file_name="adaptive_lsb_encoded_image.png",
                                mime="image/png"
                            )
                            
                            st.success("✅ Pesan berhasil disembunyikan dalam gambar menggunakan Adaptive LSB!")
                            
                    except ValueError as e:
                        st.error(f"❌ {e}")
                    except Exception as e:
                        st.error(f"❌ Terjadi error: {e}")
                else:
                    st.warning("⚠️ Masukkan pesan terlebih dahulu!")
    
    # ===== TAB 2: DECODE TEKS ADAPTIVE LSB =====
    with tab2:
        st.subheader("Baca Pesan Teks dari Gambar (Adaptive LSB)")
        
        encoded_file = st.file_uploader("Pilih gambar dengan pesan tersembunyi (Adaptive LSB):", 
                                      type=['png', 'jpg', 'jpeg'], key="decode_text_adaptive")
        
        if encoded_file is not None:
            image = Image.open(encoded_file)
            st.image(image, caption="Gambar dengan Pesan Tersembunyi (Adaptive LSB)", use_container_width=True)
            
            with st.expander("⚙️ Pengaturan Decode"):
                decode_block_size = st.slider("Ukuran Blok Decode:", min_value=4, max_value=16, value=8, 
                                            key="decode_block", help="Harus sama dengan saat encoding")
            
            if st.button("🔍 Decode Pesan dari Gambar (Adaptive LSB)", key="btn_decode_text_adaptive"):
                try:
                    with st.spinner("Mendecode pesan dengan Adaptive LSB..."):
                        decoded_message = decode_image_adaptive_lsb(image, decode_block_size)
                        
                        st.subheader("📜 Pesan yang Ditemukan:")
                        st.text_area("Pesan rahasia:", value=decoded_message, height=150, key="decoded_text_area_adaptive")
                        
                        if decoded_message.startswith("Tidak dapat"):
                            st.warning("⚠️ " + decoded_message)
                        else:
                            st.success(f"✅ Pesan berhasil diekstrak! ({len(decoded_message)} karakter)")
                            
                except Exception as e:
                    st.error(f"❌ Terjadi error: {e}")
    
    # ===== TAB 3: ENCODE GAMBAR ADAPTIVE LSB =====
    with tab3:
        st.subheader("Sembunyikan Gambar dalam Gambar (Adaptive LSB)")
        st.info("✨ **Adaptive LSB**: Menyembunyikan gambar dengan cerdas berdasarkan kompleksitas area!")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Gambar Cover** (gambar yang akan dilihat)")
            cover_image = st.file_uploader("Pilih gambar cover:", type=['png', 'jpg', 'jpeg'], key="cover_img_adaptive")
            
        with col2:
            st.write("**Gambar Rahasia** (gambar yang akan disembunyikan)")
            secret_image = st.file_uploader("Pilih gambar rahasia:", type=['png', 'jpg', 'jpeg'], key="secret_img_adaptive")
        
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
            
            with st.expander("⚙️ Pengaturan Encoding Gambar"):
                img_block_size = st.slider("Ukuran Blok:", min_value=4, max_value=16, value=8, 
                                         key="img_block", help="Ukuran blok untuk analisis kompleksitas")
            
            if st.button("🖼️ Sembunyikan Gambar (Adaptive LSB)", key="btn_encode_img_adaptive"):
                try:
                    with st.spinner("🔄 Menyembunyikan gambar menggunakan Adaptive LSB..."):
                        # Encode secret image into cover image using Adaptive LSB
                        result_image = encode_image_in_image_adaptive_lsb(cover_img, secret_img, img_block_size)
                        
                        st.success("✅ Gambar berhasil disembunyikan menggunakan Adaptive LSB!")
                        
                        # Display comparison
                        col1, col2 = st.columns(2)
                        with col1:
                            st.image(cover_img, caption="Gambar Cover Asli", use_container_width=True)
                        with col2:
                            st.image(result_image, caption="Gambar dengan Adaptive LSB", use_container_width=True)
                        
                        # Calculate PSNR
                        original_array = np.array(cover_img)
                        encoded_array = np.array(result_image)
                        mse = np.mean((original_array - encoded_array) ** 2)
                        if mse == 0:
                            psnr = 100
                        else:
                            psnr = 20 * np.log10(255.0 / np.sqrt(mse))
                        
                        st.metric("📈 Kualitas Gambar (PSNR)", f"{psnr:.2f} dB")
                        
                        # Download button
                        buf = io.BytesIO()
                        result_image.save(buf, format='PNG')
                        st.download_button(
                            label="📥 Download Gambar dengan Gambar Tersembunyi (Adaptive LSB)",
                            data=buf.getvalue(),
                            file_name="adaptive_lsb_image_in_image.png",
                            mime="image/png"
                        )
                        
                except Exception as e:
                    st.error(f"❌ Terjadi error: {e}")
    
    # ===== TAB 4: DECODE GAMBAR ADAPTIVE LSB =====
    with tab4:
        st.subheader("Ekstrak Gambar dari Gambar (Adaptive LSB)")
        
        st.write("Upload gambar yang berisi gambar tersembunyi (Adaptive LSB):")
        encoded_image_file = st.file_uploader("Pilih gambar encoded:", type=['png', 'jpg', 'jpeg'], key="decode_img_adaptive")
        
        if encoded_image_file is not None:
            encoded_img = Image.open(encoded_image_file)
            st.image(encoded_img, caption="Gambar Encoded (Adaptive LSB)", use_container_width=True)
            
            with st.expander("⚙️ Pengaturan Decode Gambar"):
                decode_img_block_size = st.slider("Ukuran Blok Decode:", min_value=4, max_value=16, value=8, 
                                                key="decode_img_block", help="Harus sama dengan saat encoding")
            
            if st.button("🔍 Ekstrak Gambar Rahasia (Adaptive LSB)", key="btn_decode_img_adaptive"):
                try:
                    with st.spinner("🔄 Mengekstrak gambar rahasia dari Adaptive LSB..."):
                        # Decode secret image from cover image using Adaptive LSB
                        secret_img_extracted = decode_image_from_image_adaptive_lsb(encoded_img, decode_img_block_size)
                        
                        st.success("✅ Gambar rahasia berhasil diekstrak dari Adaptive LSB!")
                        
                        # Display extracted image
                        st.image(secret_img_extracted, caption="Gambar Rahasia yang Ditemukan", use_container_width=True)
                        
                        # Download button for extracted image
                        buf = io.BytesIO()
                        secret_img_extracted.save(buf, format='PNG')
                        st.download_button(
                            label="📥 Download Gambar Rahasia",
                            data=buf.getvalue(),
                            file_name="extracted_secret_image_adaptive_lsb.png",
                            mime="image/png"
                        )
                        
                except Exception as e:
                    st.error(f"❌ Terjadi error: {e}")
                    st.info("💡 Tips: Pastikan ukuran blok decode sama dengan saat encoding")
    
    st.write("---")
    st.subheader("ℹ️ Tentang Steganografi Adaptive LSB")
    st.write("""
    **Apa itu Adaptive LSB?**
    
    **Adaptive LSB (Least Significant Bit)** adalah teknik steganografi cerdas yang:
    - **Menyesuaikan jumlah bit** yang digunakan berdasarkan kompleksitas area gambar
    - **Area kompleks** (tekstur tinggi) menggunakan **3 bit LSB** → lebih banyak data
    - **Area sedang** menggunakan **2 bit LSB** → keseimbangan
    - **Area halus** (plain) menggunakan **1 bit LSB** → perubahan minimal
    
    **Keunggulan Adaptive LSB:**
    
    ✅ **Kapasitas Optimal**: Area kompleks menyimpan lebih banyak data  
    ✅ **Kualitas Terjaga**: Area halus hampir tidak berubah  
    ✅ **Sulit Dideteksi**: Pola embedding tidak seragam  
    ✅ **Robust**: Lebih tahan terhadap analisis statistik  
    
    **Perbandingan Metode:**
    
    | Metode | Kapasitas | Kualitas | Keamanan |
    |--------|-----------|----------|----------|
    | **LSB Standar** | Tetap | Baik | Rendah |
    | **MSB** | Tetap | Buruk | Sedang |
    | **Adaptive LSB** | Dinamis | Sangat Baik | Tinggi |
    
    **Cara Kerja:**
    1. Gambar dibagi menjadi blok-blok kecil
    2. Setiap blok dianalisis kompleksitasnya (varians)
    3. Jumlah bit LSB yang digunakan disesuaikan dengan kompleksitas
    4. Data disembunyikan secara adaptif di seluruh gambar
    """)
