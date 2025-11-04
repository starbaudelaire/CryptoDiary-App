# Nama file: main.py (UPDATE)

import sys
from PyQt5.QtWidgets import QApplication

import db_manager
from login_window import LoginWindow
from main_window import MainWindow 

class AppController:
    def __init__(self):
        self.login_window = None
        self.main_window = None
        self.user_id = None
        self.master_key = None
        self.username = None # --- NEW: Simpan username ---
    
    def start(self):
        print("Menginisialisasi database...")
        db_manager.init_db()
        
        print("Menampilkan jendela login...")
        self.login_window = LoginWindow()
        # --- UPDATE: Hubungkan ke signal yg baru ---
        self.login_window.login_success.connect(self.on_login_complete)
        self.login_window.show()
        
    # --- UPDATE: Terima username ---
    def on_login_complete(self, user_id, master_key, username):
        print(f"Login sukses! User ID: {user_id}, Username: {username}")
        self.user_id = user_id
        self.master_key = master_key
        self.username = username # --- NEW: Simpan username ---
        
        print("Menampilkan jendela utama...")
        # --- UPDATE: Kirim username ke MainWindow ---
        self.main_window = MainWindow(self.user_id, self.master_key, self.username)
        self.main_window.show()
        
        self.login_window = None 

if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    controller = AppController()
    controller.start()
    
    sys.exit(app.exec_())