# Nama file: main.py (UPDATE)

import sys
from PyQt5.QtWidgets import QApplication

import db_manager
from login_window import LoginWindow
from main_window import MainWindow 

# GANTI SEMUA 'class AppController' DI main.py DENGAN INI:

class AppController:
    """
    Ini 'sutradara'-nya. Dia yg ngatur jendela mana yg tampil.
    """
    def __init__(self):
        self.login_window = None
        self.main_window = None
        self.user_id = None
        self.master_key = None
        self.username = None 
    
    def start(self):
        print("Menginisialisasi database...")
        db_manager.init_db()
        # Panggil fungsi baru untuk nampilin login
        self.show_login_window()
        
    def show_login_window(self):
        """Fungsi baru untuk nampilin login & nge-reset state"""
        print("Menampilkan jendela login...")
        # Reset data sesi lama (jika ada)
        self.user_id = None
        self.master_key = None
        self.username = None
        
        # Hancurin main_window lama kalo ada
        if self.main_window:
            self.main_window.close()
            self.main_window = None

        self.login_window = LoginWindow()
        self.login_window.login_success.connect(self.on_login_complete)
        self.login_window.show()
        
    def on_login_complete(self, user_id, master_key, username):
        print(f"Login sukses! User ID: {user_id}, Username: {username}")
        self.user_id = user_id
        self.master_key = master_key
        self.username = username
        
        print("Menampilkan jendela utama...")
        self.main_window = MainWindow(self.user_id, self.master_key, self.username)
        
        # --- FIX 3: Sambungin signal logout ---
        self.main_window.logout_signal.connect(self.handle_logout)
        # ------------------------------------
        
        self.main_window.show()
        
        if self.login_window:
            self.login_window.close()
            self.login_window = None 

    def handle_logout(self):
        """Fungsi ini dipanggil pas MainWindow ngirim signal logout"""
        print("Logout diproses...")
        # Tampilkan lagi jendela login
        self.show_login_window()
        
if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    controller = AppController()
    controller.start()
    
    sys.exit(app.exec_())