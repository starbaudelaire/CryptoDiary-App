# Nama file: login_window.py

import sys
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QMessageBox)
from PyQt5.QtCore import pyqtSignal

# Impor 'otak' dan 'perut' kita
import db_manager
import crypto_utils

class LoginWindow(QWidget):
    # --- Ini 'signal' penting ---
    # Saat login sukses, dia akan 'memancarkan' (emit) 2 hal:
    # 1. user_id (int)
    # 2. master_key (bytes)
    login_success = pyqtSignal(int, bytes)

    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Crypto Diary - Login')
        self.setFixedSize(300, 200)
        
        layout = QVBoxLayout()
        
        self.user_label = QLabel('Username:')
        self.user_input = QLineEdit()
        layout.addWidget(self.user_label)
        layout.addWidget(self.user_input)
        
        self.pass_label = QLabel('Password:')
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.Password) # Biar jadi bulet-bulet
        layout.addWidget(self.pass_label)
        layout.addWidget(self.pass_input)
        
        self.login_button = QPushButton('Login')
        self.login_button.clicked.connect(self._attempt_login)
        layout.addWidget(self.login_button)
        
        self.register_button = QPushButton('Register')
        self.register_button.clicked.connect(self._attempt_register)
        layout.addWidget(self.register_button)
        
        self.setLayout(layout)

    def _attempt_login(self):
        """
        Alur: GUI -> db_manager -> crypto_utils -> GUI
        """
        username = self.user_input.text()
        password = self.pass_input.text()
        
        if not username or not password:
            self._show_message('Error', 'Username dan Password tidak boleh kosong.')
            return
            
        # 1. Cek ke DB, user-nya ada nggak?
        user_data = db_manager.get_user_by_username(username)
        
        if not user_data:
            self._show_message('Login Gagal', 'Username tidak ditemukan.')
            return
            
        stored_hash, salt, user_id = user_data
        
        # 2. Kalo ada, verifikasi password-nya pake 'otak' kita
        if crypto_utils.verify_password(stored_hash, password, salt):
            # 3. KALO BERHASIL: Derivasi 'master_key' untuk sesi ini
            master_key = crypto_utils.derive_key(password, salt)
            
            self._show_message('Login Berhasil', f'Selamat datang, {username}!')
            
            # 4. Pancarkan signal sukses! Kirim user_id dan master_key
            self.login_success.emit(user_id, master_key)
            self.close() # Tutup jendela login
        else:
            self._show_message('Login Gagal', 'Password salah.')

    def _attempt_register(self):
        """
        Alur: GUI -> crypto_utils -> db_manager -> GUI
        """
        username = self.user_input.text()
        password = self.pass_input.text()
        
        if not username or not password:
            self._show_message('Error', 'Username dan Password tidak boleh kosong.')
            return
            
        # 1. Generate salt baru (unik per user)
        salt = crypto_utils.generate_salt()
        
        # 2. Hash password-nya pake salt tadi
        password_hash = crypto_utils.hash_password(password, salt)
        
        # 3. Simpen ke DB
        success, message = db_manager.register_user(username, password_hash, salt)
        
        self._show_message('Registrasi', message)

    def _show_message(self, title, message):
        """Helper buat nampilin pop-up message."""
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.setIcon(QMessageBox.Information if title.lower().find(
            'gagal') == -1 else QMessageBox.Warning)
        msg_box.exec_()