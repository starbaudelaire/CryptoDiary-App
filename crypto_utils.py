import os
import hashlib
from Crypto.Cipher import AES, Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PIL import Image

def generate_salt(size=16):
    return os.urandom(size)

def hash_password(password, salt, iterations=100000):
    return hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        salt, 
        iterations, 
        dklen=32
    )

def verify_password(stored_hash, provided_password, salt, iterations=100000):
    new_hash = hash_password(provided_password, salt, iterations)
    return new_hash == stored_hash

def derive_key(password, salt, iterations=100000):
    return hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        salt, 
        iterations, 
        dklen=32
    )

def encrypt_aes_gcm_entry(title_str, content_str, key):
    """
    Enkripsi Title dan Content (string) pakai SATU cipher object.
    Mengembalikan tuple: (title_bytes, content_bytes, nonce_bytes, tag_bytes)
    """
    try:
        title_bytes = title_str.encode('utf-8')
        content_bytes = content_str.encode('utf-8')
        
        cipher = AES.new(key, AES.MODE_GCM)
        nonce = cipher.nonce
        
        title_blob = cipher.encrypt(title_bytes)
        content_blob = cipher.encrypt(content_bytes)
        
        tag = cipher.digest()
        
        return (title_blob, content_blob, nonce, tag)
        
    except Exception as e:
        print(f"Error enkripsi AES: {e}")
        return (None, None, None, None)

def decrypt_aes_gcm_entry(title_bytes, content_bytes, key, nonce_bytes, tag_bytes):
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_bytes)
        
        title_str = cipher.decrypt(title_bytes).decode('utf-8')
        content_str = cipher.decrypt(content_bytes).decode('utf-8')
        
        cipher.verify(tag_bytes)
        
        return (title_str, content_str)
        
    except (ValueError, KeyError) as e:
        print(f"Error dekripsi/verifikasi AES: Data korup atau tag salah! {e}")
        return (None, None)
    except Exception as e:
        print(f"Error dekripsi AES: {e}")
        return (None, None)

def encrypt_aes_gcm_single(plaintext_str, key):
    try:
        plaintext_bytes = plaintext_str.encode('utf-8')
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
        nonce = cipher.nonce
        return (ciphertext, nonce, tag)
    except Exception as e:
        print(f"Error enkripsi AES single: {e}")
        return (None, None, None)

def decrypt_aes_gcm_single(ciphertext_bytes, key, nonce_bytes, tag_bytes):
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_bytes)
        plaintext_bytes = cipher.decrypt_and_verify(ciphertext_bytes, tag_bytes)
        plaintext_str = plaintext_bytes.decode('utf-8')
        return plaintext_str
    except (ValueError, KeyError) as e:
        print(f"Error dekripsi/verifikasi AES single: {e}")
        return None

def _caesar_cipher(text, shift, mode='encrypt'):
    result = ""
    if mode == 'decrypt':
        shift = -shift  
        
    for char in text:
        if 'a' <= char <= 'z':
            new_ord = (ord(char) - ord('a') + shift) % 26 + ord('a')
            result += chr(new_ord)
        elif 'A' <= char <= 'Z':
            new_ord = (ord(char) - ord('A') + shift) % 26 + ord('A')
            result += chr(new_ord)
        else:
            result += char
    return result

def _xor_cipher(text_bytes, key_str):
    """Fungsi internal untuk XOR. Bekerja pada level bytes."""
    key_bytes = key_str.encode('utf-8')
    key_len = len(key_bytes)
    
    result_bytes = bytearray()
    
    for i in range(len(text_bytes)):
        key_byte = key_bytes[i % key_len]
        
        xor_byte = text_bytes[i] ^ key_byte
        result_bytes.append(xor_byte)
        
    return bytes(result_bytes) 

def encrypt_caesar_xor(plaintext_str, shift, xor_key_str):
    try:
        caesar_result_str = _caesar_cipher(plaintext_str, shift, mode='encrypt')
        
        caesar_result_bytes = caesar_result_str.encode('utf-8')
        
        final_ciphertext_bytes = _xor_cipher(caesar_result_bytes, xor_key_str)
        
        return final_ciphertext_bytes
    except Exception as e:
        print(f"Error enkripsi Caesar+XOR: {e}")
        return None

def decrypt_caesar_xor(ciphertext_bytes, shift, xor_key_str):
    try:
        xor_decrypted_bytes = _xor_cipher(ciphertext_bytes, xor_key_str)
        
        xor_decrypted_str = xor_decrypted_bytes.decode('utf-8')
        
        final_plaintext_str = _caesar_cipher(xor_decrypted_str, shift, mode='decrypt')
        
        return final_plaintext_str
    except UnicodeDecodeError:
        print("Error dekripsi Caesar+XOR: Kunci XOR atau Shift salah.")
        return None 
    except Exception as e:
        print(f"Error dekripsi Caesar+XOR: {e}")
        return None

BLOWFISH_BLOCK_SIZE = 8

def encrypt_file_blowfish(filepath, key, output_path):
    try:
        cipher = Blowfish.new(key, Blowfish.MODE_CBC)
        iv = cipher.iv  
        
        with open(filepath, 'rb') as f_in:
            plaintext = f_in.read()
            
        padded_plaintext = pad(plaintext, BLOWFISH_BLOCK_SIZE)
        
        ciphertext = cipher.encrypt(padded_plaintext)
        
        with open(output_path, 'wb') as f_out:
            f_out.write(iv)
            f_out.write(ciphertext)
            
        return True, f"File berhasil dienkripsi ke {output_path}"
        
    except Exception as e:
        print(f"Error enkripsi file Blowfish: {e}")
        return False, f"Error: {e}"

def decrypt_file_blowfish(encrypted_filepath, key, output_path):
    try:
        with open(encrypted_filepath, 'rb') as f_in:
            iv = f_in.read(BLOWFISH_BLOCK_SIZE)
            
            ciphertext = f_in.read()

        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
        
        decrypted_padded_plaintext = cipher.decrypt(ciphertext)
        
        try:
            plaintext = unpad(decrypted_padded_plaintext, BLOWFISH_BLOCK_SIZE)
        except ValueError:
            return False, "Error: Kunci salah atau file korup (padding invalid)."

        with open(output_path, 'wb') as f_out:
            f_out.write(plaintext)
            
        return True, f"File berhasil didekripsi ke {output_path}"
        
    except Exception as e:
        print(f"Error dekripsi file Blowfish: {e}")
        return False, f"Error: {e}"


def _int_to_bytes(n):
    return n.to_bytes(4, 'big')

def _bytes_to_int(b):
    return int.from_bytes(b, 'big')

def _data_to_bits(data_bytes):
    for byte in data_bytes:
        for bit in format(byte, '08b'):
            yield int(bit) 

def _modify_pixel_lsb(pixel_tuple, bit):
    val = pixel_tuple[0] 
    
    new_val = (val & 254) | bit
    
    if len(pixel_tuple) == 4:
        return (new_val, pixel_tuple[1], pixel_tuple[2], pixel_tuple[3])
    else: 
        return (new_val, pixel_tuple[1], pixel_tuple[2])

def _extract_pixel_lsb(pixel_tuple):
    val = pixel_tuple[0] 
    return val & 1

def embed_lsb(image_path, payload_bytes, output_path):
    try:
        img = Image.open(image_path).convert('RGBA') 
        width, height = img.size
        pixels = img.load()
        
        payload_len = len(payload_bytes)
        len_header_bytes = _int_to_bytes(payload_len) 
        
        data_to_embed = len_header_bytes + payload_bytes
        total_bits_to_embed = len(data_to_embed) * 8
        
        max_bits = width * height
        if total_bits_to_embed > max_bits:
            return False, f"Error: Gambar terlalu kecil. Butuh {total_bits_to_embed} bits, tersedia {max_bits}."

        bit_stream = _data_to_bits(data_to_embed)
        
        bit_count = 0
        for y in range(height):
            for x in range(width):
                if bit_count < total_bits_to_embed:
                    try:
                        bit_to_embed = next(bit_stream)
                    except StopIteration:
                        break 
                    
                    current_pixel = pixels[x, y]
                    
                    new_pixel = _modify_pixel_lsb(current_pixel, bit_to_embed)
                    
                    pixels[x, y] = new_pixel
                    bit_count += 1
                else:
                    break 
            if bit_count >= total_bits_to_embed:
                break 
        
        img.save(output_path, "PNG")
        img.close()
        return True, f"Pesan berhasil disembunyikan di {output_path}"

    except FileNotFoundError:
        return False, "Error: File gambar tidak ditemukan."
    except Exception as e:
        return False, f"Error LSB embed: {e}"

def extract_lsb(stego_image_path):
    try:
        img = Image.open(stego_image_path).convert('RGBA')
        width, height = img.size
        pixels = img.load()
        
        extracted_bits = []
        
        for y in range(height):
            for x in range(width):
                if len(extracted_bits) < 32: 
                    current_pixel = pixels[x, y]
                    extracted_bits.append(_extract_pixel_lsb(current_pixel))
                else:
                    break
            if len(extracted_bits) >= 32:
                break
        
        header_bytes = b""
        for i in range(0, 32, 8):
            byte_str = "".join(map(str, extracted_bits[i:i+8]))
            header_bytes += bytes([int(byte_str, 2)])
            
        payload_len = _bytes_to_int(header_bytes)
        total_bits_to_read = 32 + (payload_len * 8) 
        
        for y in range(height):
            for x in range(width):
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