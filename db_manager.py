# Nama file: db_manager.py

import sqlite3
import os

DB_FILE = "crypto_diary.db"

def init_db():
    """
    Fungsi ini adalah 'tutorial' bikin DB-nya.
    Dia bakal nge-create file DB dan tabelnya kalo belum ada.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # --- Tabel 1: users ---
    # Sesuai skema kita: id, username, password_hash (teks), salt (bytes/BLOB)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash BLOB NOT NULL, 
        salt BLOB NOT NULL
    );
    """)
    
    # --- Tabel 2: diary_entries ---
    # Sesuai skema: id, user_id (link ke tabel users),
    # title & content (BLOB, karena ciphertext),
    # nonce & tag (BLOB, untuk AES-GCM)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS diary_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title BLOB NOT NULL,
        content BLOB NOT NULL,
        nonce BLOB NOT NULL,
        tag BLOB NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );
    """)
    
    conn.commit()
    conn.close()
    print(f"Database '{DB_FILE}' berhasil diinisialisasi.")

def register_user(username, password_hash, salt):
    """Menyimpan user baru ke DB."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        # Kita simpan hash dan salt
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            (username, password_hash, salt)
        )
        conn.commit()
        conn.close()
        return True, "Registrasi berhasil."
    except sqlite3.IntegrityError:
        # Ini terjadi kalo username-nya udah ada (UNIQUE constraint)
        return False, "Username sudah terdaftar."
    except Exception as e:
        return False, f"Terjadi error: {e}"

def get_user_by_username(username):
    """
    Mengambil data user (hash & salt) untuk verifikasi login.
    Mengembalikan tuple (password_hash, salt, user_id) atau None.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password_hash, salt, id FROM users WHERE username = ?",
        (username,)
    )
    user_data = cursor.fetchone() # Ambil 1 baris hasil
    conn.close()
    
    if user_data:
        return user_data
    else:
        return None

def save_diary_entry(user_id, title_blob, content_blob, nonce, tag):
    """Menyimpan (atau update) entry diary terenkripsi."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        # Untuk simplicity, kita insert aja dulu. Nanti bisa ditambahin logic update.
        cursor.execute(
            "INSERT INTO diary_entries (user_id, title, content, nonce, tag) VALUES (?, ?, ?, ?, ?)",
            (user_id, title_blob, content_blob, nonce, tag)
        )
        conn.commit()
        conn.close()
        return True, "Catatan berhasil disimpan."
    except Exception as e:
        return False, f"Gagal menyimpan catatan: {e}"

def get_diary_entries(user_id):
    """Mengambil SEMUA entry diary terenkripsi milik user."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        # Ambil semua data yg dibutuhkan untuk dekripsi
        cursor.execute(
            "SELECT id, title, content, nonce, tag, timestamp FROM diary_entries WHERE user_id = ? ORDER BY timestamp DESC",
            (user_id,)
        )
        entries = cursor.fetchall()
        conn.close()
        return entries # Ini bakal jadi list of tuples
    except Exception as e:
        print(f"Gagal mengambil catatan: {e}")
        return []

def update_diary_entry(entry_id, title_blob, content_blob, nonce, tag):
    """Mengupdate entry diary yang sudah ada."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE diary_entries 
            SET title = ?, content = ?, nonce = ?, tag = ?, timestamp = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (title_blob, content_blob, nonce, tag, entry_id)
        )
        conn.commit()
        conn.close()
        return True, "Catatan berhasil diupdate."
    except Exception as e:
        return False, f"Gagal mengupdate catatan: {e}"

def delete_diary_entry(entry_id):
    """Menghapus entry diary berdasarkan ID-nya."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM diary_entries WHERE id = ?", (entry_id,))
        conn.commit()
        conn.close()
        return True, "Catatan berhasil dihapus."
    except Exception as e:
        return False, f"Gagal menghapus catatan: {e}"

# --- Tes Sederhana (opsional, bisa dihapus nanti) ---
if __name__ == "__main__":
    init_db() 
    # Coba cek, file 'crypto_diary.db' harusnya muncul di folder lu.