# Nama file: crypto_utils.py

import os
import hashlib
# Kita akan pakai library PyCryptodome, pastikan sudah install:
# pip install pycryptodomex
# (atau 'pip install pycryptodome' kalo yg atas error)
from Crypto.Cipher import AES, Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PIL import Image

# --- BAGIAN 1: AUTENTIKASI & KEY DERIVATION ---

def generate_salt(size=16):
    """Menghasilkan 16 bytes (128 bits) salt acak."""
    return os.urandom(size)

def hash_password(password, salt, iterations=100000):
    """
    Hash password menggunakan PBKDF2-HMAC-SHA256.
    Ini yang akan disimpan di DB.
    """
    # password.encode('utf-8') -> ubah string jadi bytes
    # dklen=32 -> minta output hash 32 bytes (256 bits)
    return hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        salt, 
        iterations, 
        dklen=32
    )

def verify_password(stored_hash, provided_password, salt, iterations=100000):
    """
    Verifikasi password yg diinput user dengan hash di DB.
    """
    # Kita hash lagi password yg diinput...
    new_hash = hash_password(provided_password, salt, iterations)
    # ...lalu bandingkan hasilnya.
    return new_hash == stored_hash

def derive_key(password, salt, iterations=100000):
    """
    INI FUNGSI KUNCI (literally).
    Fungsi ini BUKAN untuk verifikasi login, tapi untuk
    menghasilkan 'MASTER KEY' 32-byte (256-bit) yang akan kita 
    pakai untuk enkripsi/dekripsi AES dan Blowfish selama sesi berlangsung.
    """
    # Kita pakai PBKDF2 lagi. Aman dan konsisten.
    # Kita minta 32 bytes (256-bit) -> cocok untuk AES-256
    return hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        salt, 
        iterations, 
        dklen=32
    )

# ...(kode dari Bagian 1: Auth & KDF ada di atas sini)...

# --- BAGIAN 2: AES (untuk Database Diary) ---

def encrypt_aes_gcm(plaintext_str, key):
    """
    Enkripsi data (string) menggunakan AES-GCM dengan key 256-bit (32 bytes).
    Mengembalikan tuple: (ciphertext_bytes, nonce_bytes, tag_bytes)
    """
    try:
        # 1. Ubah plaintext (string) jadi bytes
        plaintext_bytes = plaintext_str.encode('utf-8')
        
        # 2. Buat cipher AES baru pake mode GCM dan key yg kita punya
        # AES.new() butuh key, mode, dan nonce (atau biarin random)
        cipher = AES.new(key, AES.MODE_GCM)
        
        # 3. Lakukan enkripsi. 
        #    Fungsi .encrypt_and_digest() ini keren, 
        #    dia sekaligus enkrip DAN ngitung 'tag' autentikasi.
        ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
        
        # 4. Ambil nonce yg tadi di-generate otomatis sama cipher-nya
        nonce = cipher.nonce
        
        # 5. Kembalikan semua yg dibutuhkan untuk dekripsi nanti
        #    ciphertext: data terenkripsi
        #    nonce: 'kunci' acak biar enkripsi beda terus (WAJIB DISIMPAN)
        #    tag: 'segel' digital untuk buktiin data nggak diubah (WAJIB DISIMPAN)
        return (ciphertext, nonce, tag)
        
    except Exception as e:
        print(f"Error enkripsi AES: {e}")
        return (None, None, None)

def decrypt_aes_gcm(ciphertext_bytes, key, nonce_bytes, tag_bytes):
    """
    Dekripsi data (bytes) menggunakan AES-GCM.
    Fungsi ini akan VERIFIKASI 'tag' dulu sebelum dekripsi.
    Mengembalikan: plaintext (string) atau None jika gagal (misal data korup/diubah)
    """
    try:
        # 1. Buat ulang cipher-nya, kali ini HARUS pake key DAN nonce yg sama
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_bytes)
        
        # 2. Lakukan dekripsi DAN verifikasi.
        #    Fungsi .decrypt_and_verify() ini yang ngecek 'tag'.
        #    Kalo tag-nya beda (artinya ciphertext atau tag-nya diubah),
        #    dia bakal otomatis raise ValueError. Aman.
        plaintext_bytes = cipher.decrypt_and_verify(ciphertext_bytes, tag_bytes)
        
        # 3. Ubah hasil dekripsi (bytes) jadi string lagi
        plaintext_str = plaintext_bytes.decode('utf-8')
        
        return plaintext_str
        
    except (ValueError, KeyError) as e:
        # Ini error kalo verifikasi tag gagal.
        print(f"Error dekripsi/verifikasi AES: Data mungkin korup atau diubah! {e}")
        return None
    except Exception as e:
        print(f"Error dekripsi AES: {e}")
        return None

# ...(kode dari Bagian 1 & 2 ada di atas sini)...

# --- BAGIAN 3: Teks Super (Caesar Cipher + XOR) ---

def _caesar_cipher(text, shift, mode='encrypt'):
    """Fungsi internal untuk Caesar Cipher. Hanya memproses huruf A-Z."""
    result = ""
    if mode == 'decrypt':
        shift = -shift  # Balik pergeserannya untuk dekripsi
        
    for char in text:
        if 'a' <= char <= 'z':
            # Rumus: C = (P + k) mod 26
            # ord('a') = 97
            new_ord = (ord(char) - ord('a') + shift) % 26 + ord('a')
            result += chr(new_ord)
        elif 'A' <= char <= 'Z':
            # Rumus yg sama untuk huruf besar
            # ord('A') = 65
            new_ord = (ord(char) - ord('A') + shift) % 26 + ord('A')
            result += chr(new_ord)
        else:
            # Kalo bukan huruf (spasi, angka, simbol), biarin aja
            result += char
    return result

def _xor_cipher(text_bytes, key_str):
    """Fungsi internal untuk XOR. Bekerja pada level bytes."""
    key_bytes = key_str.encode('utf-8')
    key_len = len(key_bytes)
    
    # Kita pake 'bytearray' biar bisa diubah-ubah (mutable)
    result_bytes = bytearray()
    
    # Loop sebanyak bytes di teks
    for i in range(len(text_bytes)):
        # Ini adalah 'repeating key XOR' (Vigenere modern)
        # Ambil byte kunci pake 'i % key_len' biar kuncinya ngulang
        key_byte = key_bytes[i % key_len]
        
        # Operasi XOR (simbol ^)
        xor_byte = text_bytes[i] ^ key_byte
        result_bytes.append(xor_byte)
        
    return bytes(result_bytes) # Kembalikan sebagai 'bytes' (immutable)

def encrypt_caesar_xor(plaintext_str, shift, xor_key_str):
    """
    Enkripsi Super: Layer 1 (Caesar) -> Layer 2 (XOR).
    Mengembalikan: ciphertext (bytes)
    """
    try:
        # Layer 1: Caesar Cipher (String -> String)
        caesar_result_str = _caesar_cipher(plaintext_str, shift, mode='encrypt')
        
        # Ubah hasil Caesar (string) jadi bytes untuk di-XOR
        caesar_result_bytes = caesar_result_str.encode('utf-8')
        
        # Layer 2: XOR (Bytes -> Bytes)
        final_ciphertext_bytes = _xor_cipher(caesar_result_bytes, xor_key_str)
        
        return final_ciphertext_bytes
    except Exception as e:
        print(f"Error enkripsi Caesar+XOR: {e}")
        return None

def decrypt_caesar_xor(ciphertext_bytes, shift, xor_key_str):
    """
    Dekripsi Super: Layer 1 (XOR) -> Layer 2 (Caesar).
    Mengembalikan: plaintext (string) atau None
    """
    try:
        # Layer 1: Balikin XOR (Bytes -> Bytes)
        # Asik-nya, dekripsi XOR = enkripsi XOR
        xor_decrypted_bytes = _xor_cipher(ciphertext_bytes, xor_key_str)
        
        # Ubah hasil dekripsi XOR (bytes) jadi string
        xor_decrypted_str = xor_decrypted_bytes.decode('utf-8')
        
        # Layer 2: Balikin Caesar (String -> String)
        final_plaintext_str = _caesar_cipher(xor_decrypted_str, shift, mode='decrypt')
        
        return final_plaintext_str
    except UnicodeDecodeError:
        print("Error dekripsi Caesar+XOR: Kunci XOR atau Shift salah.")
        return None # Ini kejadian kalo kuncinya salah
    except Exception as e:
        print(f"Error dekripsi Caesar+XOR: {e}")
        return None

# ...(kode dari Bagian 1, 2, & 3 ada di atas sini)...

# --- BAGIAN 4: Blowfish (untuk Enkripsi File) ---

# Ukuran block Blowfish adalah 8 bytes (64-bit)
BLOWFISH_BLOCK_SIZE = 8

def encrypt_file_blowfish(filepath, key, output_path):
    """
    Enkripsi file pakai Blowfish-CBC dengan key (32 bytes).
    Format file output: [ 8 bytes IV ] [ ... ciphertext ... ]
    """
    try:
        # 1. Buat cipher Blowfish baru pake mode CBC
        #    Kita generate IV acak 8-byte
        cipher = Blowfish.new(key, Blowfish.MODE_CBC)
        iv = cipher.iv  # Ambil IV 8-byte yg di-generate
        
        # 2. Buka file input (plaintext) untuk dibaca 'rb' (read binary)
        with open(filepath, 'rb') as f_in:
            plaintext = f_in.read()
            
        # 3. Lakukan padding pada plaintext
        #    Biar ukurannya pas kelipatan 8 bytes (block size)
        padded_plaintext = pad(plaintext, BLOWFISH_BLOCK_SIZE)
        
        # 4. Enkripsi data
        ciphertext = cipher.encrypt(padded_plaintext)
        
        # 5. Tulis ke file output 'wb' (write binary)
        with open(output_path, 'wb') as f_out:
            # PENTING: Tulis IV-nya dulu di awal file!
            f_out.write(iv)
            # Baru tulis sisa ciphertext-nya
            f_out.write(ciphertext)
            
        return True, f"File berhasil dienkripsi ke {output_path}"
        
    except Exception as e:
        print(f"Error enkripsi file Blowfish: {e}")
        return False, f"Error: {e}"

def decrypt_file_blowfish(encrypted_filepath, key, output_path):
    """
    Dekripsi file Blowfish-CBC (yg formatnya: [ 8 bytes IV ] [ ... ciphertext ... ])
    """
    try:
        # 1. Buka file terenkripsi 'rb' (read binary)
        with open(encrypted_filepath, 'rb') as f_in:
            # 2. Baca 8 bytes PERTAMA sebagai IV
            iv = f_in.read(BLOWFISH_BLOCK_SIZE)
            
            # 3. Baca sisa file-nya sebagai ciphertext
            ciphertext = f_in.read()

        # 4. Buat ulang cipher-nya, PAKE key dan IV yg tadi kita baca
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
        
        # 5. Dekripsi ciphertext
        decrypted_padded_plaintext = cipher.decrypt(ciphertext)
        
        # 6. Hapus padding dari hasil dekripsi
        try:
            plaintext = unpad(decrypted_padded_plaintext, BLOWFISH_BLOCK_SIZE)
        except ValueError:
            # Ini kejadian kalo key-nya salah atau file-nya korup
            return False, "Error: Kunci salah atau file korup (padding invalid)."

        # 7. Tulis plaintext (hasil akhir) ke file output
        with open(output_path, 'wb') as f_out:
            f_out.write(plaintext)
            
        return True, f"File berhasil didekripsi ke {output_path}"
        
    except Exception as e:
        print(f"Error dekripsi file Blowfish: {e}")
        return False, f"Error: {e}"

# ...(kode dari Bagian 1, 2, 3, & 4 ada di atas sini)...

# --- BAGIAN 5: Steganografi (LSB) ---

def _int_to_bytes(n):
    """Ubah integer (panjang data) jadi 4 bytes (32-bit)."""
    # 'big' endian, 4 bytes
    return n.to_bytes(4, 'big')

def _bytes_to_int(b):
    """Ubah 4 bytes (header) balik jadi integer."""
    return int.from_bytes(b, 'big')

def _data_to_bits(data_bytes):
    """
    Ubah stream bytes (misal: b'abc') jadi iterator bit 
    (misal: 0,1,1,0,0,0,0,1, 0,1,1,0,0,0,1,0, ...)
    """
    for byte in data_bytes:
        # '08b' = format jadi 8-bit binary (e.g., '01100001')
        for bit in format(byte, '08b'):
            yield int(bit) # hasilin 0 atau 1

def _modify_pixel_lsb(pixel_tuple, bit):
    """
    Modifikasi LSB dari salah satu channel (R, G, atau B) di piksel.
    pixel_tuple = (R, G, B, A) atau (R, G, B)
    """
    # Kita cuma main di R, G, B. (index 0, 1, 2)
    # Kita pilih satu channel aja, misal R (index 0)
    # Ini bisa di-improve biar pake R, G, B gantian, tapi ini yg paling simpel
    
    val = pixel_tuple[0] # Ambil nilai R
    
    # Cara gampang set LSB:
    # 1. 'val & 254' -> bikin LSB jadi 0 (misal: 10101011 -> 10101010)
    # 2. '... | bit'   -> set LSB-nya jadi 'bit' (0 atau 1)
    new_val = (val & 254) | bit
    
    # Kembalikan tuple piksel baru
    if len(pixel_tuple) == 4: # RGBA
        return (new_val, pixel_tuple[1], pixel_tuple[2], pixel_tuple[3])
    else: # RGB
        return (new_val, pixel_tuple[1], pixel_tuple[2])

def _extract_pixel_lsb(pixel_tuple):
    """Ekstrak LSB (bit 0 atau 1) dari channel R."""
    val = pixel_tuple[0] # Ambil nilai R
    # 'val & 1' akan menghasilkan 1 kalo LSB-nya 1, dan 0 kalo LSB-nya 0
    return val & 1

def embed_lsb(image_path, payload_bytes, output_path):
    """
    Sembunyikan payload (bytes) ke dalam LSB gambar PNG.
    Alur: [ 4-byte Header Panjang ] [ Payload ... ]
    """
    try:
        # 1. Buka gambar
        img = Image.open(image_path).convert('RGBA') # Paksa ke RGBA biar konsisten
        width, height = img.size
        pixels = img.load()
        
        # 2. Siapin data yg mau disembunyiin
        payload_len = len(payload_bytes)
        len_header_bytes = _int_to_bytes(payload_len) # 4 bytes
        
        # Data total = 4 byte header + payload-nya
        data_to_embed = len_header_bytes + payload_bytes
        total_bits_to_embed = len(data_to_embed) * 8
        
        # 3. Cek kapasitas gambar
        # Kita cuma pake 1 bit per piksel (di channel R)
        max_bits = width * height
        if total_bits_to_embed > max_bits:
            return False, f"Error: Gambar terlalu kecil. Butuh {total_bits_to_embed} bits, tersedia {max_bits}."

        # 4. Buat bit iterator
        bit_stream = _data_to_bits(data_to_embed)
        
        # 5. Mulai proses embedding
        bit_count = 0
        for y in range(height):
            for x in range(width):
                if bit_count < total_bits_to_embed:
                    # Ambil bit selanjutnya
                    try:
                        bit_to_embed = next(bit_stream)
                    except StopIteration:
                        break # Harusnya nggak kejadian, tapi just in case
                    
                    # Ambil piksel asli
                    current_pixel = pixels[x, y]
                    
                    # Modifikasi LSB-nya
                    new_pixel = _modify_pixel_lsb(current_pixel, bit_to_embed)
                    
                    # Taruh piksel baru ke gambar
                    pixels[x, y] = new_pixel
                    bit_count += 1
                else:
                    break # Semua bit sudah di-embed
            if bit_count >= total_bits_to_embed:
                break # Selesai
        
        # 6. Simpan gambar baru
        img.save(output_path, "PNG")
        img.close()
        return True, f"Pesan berhasil disembunyikan di {output_path}"

    except FileNotFoundError:
        return False, "Error: File gambar tidak ditemukan."
    except Exception as e:
        return False, f"Error LSB embed: {e}"

def extract_lsb(stego_image_path):
    """
    Ekstrak payload (bytes) dari LSB gambar PNG.
    Alur: Baca 4-byte Header -> Tentukan Panjang -> Baca sisa Payload
    """
    try:
        img = Image.open(stego_image_path).convert('RGBA')
        width, height = img.size
        pixels = img.load()
        
        extracted_bits = []
        
        # --- Fase 1: Ekstrak Header (32 bits / 4 bytes) ---
        for y in range(height):
            for x in range(width):
                if len(extracted_bits) < 32: # 32 bits = 4 bytes
                    current_pixel = pixels[x, y]
                    extracted_bits.append(_extract_pixel_lsb(current_pixel))
                else:
                    break
            if len(extracted_bits) >= 32:
                break
        
        # Ubah 32 bits pertama jadi bytes, lalu jadi integer
        header_bytes = b""
        for i in range(0, 32, 8):
            byte_str = "".join(map(str, extracted_bits[i:i+8]))
            header_bytes += bytes([int(byte_str, 2)])
            
        payload_len = _bytes_to_int(header_bytes)
        total_bits_to_read = 32 + (payload_len * 8) # Total = 32 bit header + (panjang payload x 8)
        
        # --- Fase 2: Ekstrak sisa data (Payload) ---
        # Kita udah baca 32 bit, jadi kita lanjutin
        for y in range(height):
            for x in range(width):
                # Skip piksel yg udah dibaca buat header
                pixel_index = (y * width) + x
                if pixel_index < 32: 
                    continue
                    
                if len(extracted_bits) < total_bits_to_read:
                    current_pixel = pixels[x, y]
                    extracted_bits.append(_extract_pixel_lsb(current_pixel))
                else:
                    break
            if len(extracted_bits) >= total_bits_to_read:
                break

        if len(extracted_bits) < total_bits_to_read:
            return None, "Error: Ekstraksi gagal, data tidak lengkap (mungkin bukan stego-image)."

        # --- Fase 3: Konversi bit-stream jadi bytes ---
        # Kita skip 32 bit pertama (header), ambil payload-nya aja
        payload_bits = extracted_bits[32:]
        payload_bytes = b""
        
        for i in range(0, len(payload_bits), 8):
            byte_str = "".join(map(str, payload_bits[i:i+8]))
            payload_bytes += bytes([int(byte_str, 2)])
            
        img.close()
        return payload_bytes, "Ekstraksi berhasil."

    except FileNotFoundError:
        return None, "Error: File stego-image tidak ditemukan."
    except Exception as e:
        return None, f"Error LSB extract: {e}"