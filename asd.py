
with tab2:
    st.subheader("Daftar Mobil (Hasil Dekripsi)")
    
    cars, successful_decrypts, total_cars = read_cars(encryption_key)
    
    if total_cars > 0:
        if successful_decrypts == total_cars:
            st.success(f"✅ Semua {total_cars} mobil berhasil didekripsi dengan kunci ini!")
        elif successful_decrypts > 0:
            st.warning(f"⚠️ {successful_decrypts} dari {total_cars} mobil berhasil didekripsi.")
        else:
            st.error(f"❌ Tidak ada data yang berhasil didekripsi dengan kunci ini.")
    
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
                        st.write(f"**Brand:** {brand}")
                        st.write(f"**Model:** {model}")
                    else:
                        st.write(f"~~Brand: {brand}~~")
                        st.write(f"~~Model: {model}~~")
                    st.caption(f"ID: {car_id}")
                
                with col2:
                    if isinstance(price, (int, float)):
                        st.write(f"**Harga:** Rp {price:,.0f}")
                    else:
                        st.write(f"**Harga:** {price}")
                
                with col3:
                    st.write("**Dekripsi Mobil:**")
                    if dekripsi_mobil and dekripsi_mobil != "[EMPTY]":
                        # PERBAIKAN: Tampilkan seluruh teks tanpa pemotongan
                        with st.expander("📋 Lihat Deskripsi Lengkap"):
                            st.text_area(
                                "Salin teks ini untuk didekripsi:",
                                value=dekripsi_mobil,
                                key=f"desc_{car_id}",
                                height=150,
                                label_visibility="collapsed"
                            )
                            st.caption("🔍 Salin teks di atas dan paste di halaman Super Encryption untuk didekripsi")
                    else:
                        st.info("Belum diisi")
                
                with col4:
                    if st.button("🗑️", key=f"delete_{car_id}"):
                        if delete_car(car_id):
                            st.success("✅ Data dihapus!")
                            st.rerun()
                        else:
                            st.error("❌ Gagal menghapus data")
                
                st.markdown('</div>', unsafe_allow_html=True)
                st.divider()