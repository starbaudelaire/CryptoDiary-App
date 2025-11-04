import sqlite3
import os

DB_FILE = "crypto_diary.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash BLOB NOT NULL, 
        salt BLOB NOT NULL
    );
    """)
    
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
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        # simpan hash dan salt
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            (username, password_hash, salt)
        )
        conn.commit()
        conn.close()
        return True, "Registrasi berhasil."
    except sqlite3.IntegrityError:
        return False, "Username sudah terdaftar."
    except Exception as e:
        return False, f"Terjadi error: {e}"

def get_user_by_username(username):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password_hash, salt, id FROM users WHERE username = ?",
        (username,)
    )
    user_data = cursor.fetchone() 
    conn.close()
    
    if user_data:
        return user_data
    else:
        return None

def save_diary_entry(user_id, title_blob, content_blob, nonce, tag):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
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
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, title, content, nonce, tag, timestamp FROM diary_entries WHERE user_id = ? ORDER BY timestamp DESC",
            (user_id,)
        )
        entries = cursor.fetchall()
        conn.close()
        return entries 
    except Exception as e:
        print(f"Gagal mengambil catatan: {e}")
        return []

def update_diary_entry(entry_id, title_blob, content_blob, nonce, tag):
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