# Nama file: main.py (VERSI UPDATE)

import sys
from PyQt5.QtWidgets import QApplication

# Impor file-file kita
import db_manager
from login_window import LoginWindow
from main_window import MainWindow # <-- TAMBAHKAN INI

class AppController:
    """
    Ini 'sutradara'-nya. Dia yg ngatur jendela mana yg tampil.
    """
    def __init__(self):
        self.login_window = None
        self.main_window = None
        self.user_id = None
        self.master_key = None
    
    def start(self):
        # 1. Inisialisasi Database dulu (bikin file & tabel kalo blm ada)
        print("Menginisialisasi database...")
        db_manager.init_db()
        
        # 2. Tampilkan jendela login
        print("Menampilkan jendela login...")
        self.login_window = LoginWindow()
        # Hubungkan signal 'login_success' ke fungsi 'on_login_complete'
        self.login_window.login_success.connect(self.on_login_complete)
        self.login_window.show()
        
    def on_login_complete(self, user_id, master_key):
        """
        Ini fungsi yg kepanggil KALO login sukses.
        """
        print(f"Login sukses! User ID: {user_id}")
        self.user_id = user_id
        self.master_key = master_key
        
        # --- (BAGIAN INI KITA AKTIFKAN) ---
        print("Menampilkan jendela utama...")
        # Buat MainWindow dan kirim data sesi-nya (user_id & master_key)
        self.main_window = MainWindow(self.user_id, self.master_key)
        self.main_window.show()
        
        # Jendela login ditutup (otomatis dari dlm login_window.py)
        self.login_window = None 

# --- Titik Masuk Utama Aplikasi ---
if __name__ == '__main__':
    # Bikin aplikasi PyQt
    app = QApplication(sys.argv)
    
    # Bikin 'sutradara'
    controller = AppController()
    
    # Mulai aplikasi
    controller.start()
    
    # Jalankan event loop-nya
    sys.exit(app.exec_())