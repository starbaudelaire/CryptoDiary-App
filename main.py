import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QPalette

import db_manager
from login_window import LoginWindow
from main_window import MainWindow 

class AppController:
    def __init__(self):
        self.login_window = None
        self.main_window = None
        self.user_id = None
        self.master_key = None
        self.username = None 
    
    def start(self):
        print("Menginisialisasi database...")
        db_manager.init_db()
        self.show_login_window()
        
    def show_login_window(self):
        print("Menampilkan jendela login...")
        self.user_id = None
        self.master_key = None
        self.username = None
        
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
        
        self.main_window.logout_signal.connect(self.handle_logout)
        
        self.main_window.show()
        
        if self.login_window:
            self.login_window.close()
            self.login_window = None 

    def handle_logout(self):
        """Fungsi ini dipanggil pas MainWindow ngirim signal logout"""
        print("Logout diproses...")
        
        from PyQt5.QtWidgets import QApplication
        from PyQt5.QtGui import QPalette
        QApplication.instance().setPalette(QApplication.instance().style().standardPalette())
        
        self.show_login_window()
        
if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    controller = AppController()
    controller.start()
    
    sys.exit(app.exec_())