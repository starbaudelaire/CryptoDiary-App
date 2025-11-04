import sys
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QMessageBox)
from PyQt5.QtCore import pyqtSignal, Qt
import db_manager
import crypto_utils

class LoginWindow(QWidget):
    login_success = pyqtSignal(int, bytes, str) 

    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Crypto Diary - Login')
        self.setFixedSize(350, 250) 
        
        layout = QVBoxLayout()
        layout.setSpacing(10) 
        layout.setAlignment(Qt.AlignCenter) 

        self.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
                color: #333; /* Dark gray for text */
            }
            QLineEdit {
                padding: 8px;
                border: 1px solid #ccc;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton {
                background-color: #4CAF50; /* Green */
                color: white;
                padding: 10px;
                border: none;
                border-radius: 5px;
                font-size: 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049; /* Darker green on hover */
            }
        """)
        
        self.user_label = QLabel('Username:')
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Masukkan username Anda")
        layout.addWidget(self.user_label)
        layout.addWidget(self.user_input)
        
        self.pass_label = QLabel('Password:')
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.Password)
        self.pass_input.setPlaceholderText("Masukkan password Anda")
        layout.addWidget(self.pass_label)
        layout.addWidget(self.pass_input)
        
        layout.addSpacing(15)

        self.login_button = QPushButton('Login')
        self.login_button.clicked.connect(self._attempt_login)
        layout.addWidget(self.login_button)
        
        self.register_button = QPushButton('Register')
        self.register_button.setStyleSheet("""
            QPushButton {
                background-color: #007bff; /* Blue */
                color: white;
                padding: 10px;
                border: none;
                border-radius: 5px;
                font-size: 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0056b3; /* Darker blue on hover */
            }
        """)
        self.register_button.clicked.connect(self._attempt_register)
        layout.addWidget(self.register_button)
        
        self.setLayout(layout)

    def _attempt_login(self):
        username = self.user_input.text()
        password = self.pass_input.text()
        
        if not username or not password:
            self._show_message('Error', 'Username dan Password tidak boleh kosong.')
            return
            
        user_data = db_manager.get_user_by_username(username)
        
        if not user_data:
            self._show_message('Login Gagal', 'Username tidak ditemukan.')
            return
            
        stored_hash, salt, user_id = user_data
        
        if crypto_utils.verify_password(stored_hash, password, salt):
            master_key = crypto_utils.derive_key(password, salt)
            
            self._show_message('Login Berhasil', f'Selamat datang, {username}!')
            
            self.login_success.emit(user_id, master_key, username)
            self.close()
        else:
            self._show_message('Login Gagal', 'Password salah.')

    def _attempt_register(self):
        username = self.user_input.text()
        password = self.pass_input.text()
        
        if not username or not password:
            self._show_message('Error', 'Username dan Password tidak boleh kosong.')
            return
            
        salt = crypto_utils.generate_salt()
        password_hash = crypto_utils.hash_password(password, salt)
        
        success, message = db_manager.register_user(username, password_hash, salt)
        
        self._show_message('Registrasi', message)

    def _show_message(self, title, message):
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.setIcon(QMessageBox.Information if title.lower().find('gagal') == -1 else QMessageBox.Warning)
        msg_box.exec_()