# Nama file: main_window.py (ROMBAK TOTAL)

import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QStackedWidget, QLabel, QLineEdit,
                             QPushButton, QTextEdit, QListWidget, QFileDialog,
                             QMessageBox, QInputDialog, QListWidgetItem,
                             QFormLayout, QToolBar, QAction, QToolButton)
from PyQt5.QtGui import QIcon, QPalette, QColor, QIntValidator
from PyQt5.QtCore import Qt, QSize
import os

import db_manager
import crypto_utils

# --- Sub-Widget untuk Tiap Fitur (biar rapi) ---

class DiaryTabWidget(QWidget):
    def __init__(self, user_id, master_key, parent=None):
        super().__init__(parent)
        self.user_id = user_id
        self.master_key = master_key
        self._init_ui()
        self._load_diary_entries()

    def _init_ui(self):
        layout = QHBoxLayout(self)
        
        # Kolom Kiri: List Judul
        left_layout = QVBoxLayout()
        left_layout.addWidget(QLabel("<H3>Catatan Terenkripsi:</H3>"))
        self.diary_list = QListWidget()
        self.diary_list.itemClicked.connect(self._display_diary_entry)
        left_layout.addWidget(self.diary_list)
        
        # Kolom Kanan: Editor Teks
        right_layout = QVBoxLayout()
        right_layout.addWidget(QLabel("<H3>Judul Catatan:</H3>"))
        self.diary_title = QLineEdit()
        self.diary_title.setPlaceholderText("Masukkan judul catatan Anda...")
        right_layout.addWidget(self.diary_title)
        
        right_layout.addWidget(QLabel("<H3>Isi Catatan:</H3>"))
        self.diary_content = QTextEdit()
        self.diary_content.setPlaceholderText("Tulis isi catatan Anda di sini...")
        right_layout.addWidget(self.diary_content)
        
        btn_layout = QHBoxLayout()
        self.save_btn = QPushButton("Simpan Catatan Baru")
        self.save_btn.setStyleSheet("background-color: #28a745; color: white;")
        self.save_btn.clicked.connect(self._save_diary_entry)
        btn_layout.addWidget(self.save_btn)
        
        self.clear_btn = QPushButton("Clear Form")
        self.clear_btn.setStyleSheet("background-color: #007bff; color: white;")
        self.clear_btn.clicked.connect(self._clear_diary_form)
        btn_layout.addWidget(self.clear_btn)

        self.delete_btn = QPushButton("Hapus Catatan")
        self.delete_btn.setStyleSheet("background-color: #dc3545; color: white;")
        self.delete_btn.clicked.connect(self._delete_diary_entry)
        btn_layout.addWidget(self.delete_btn)
        
        right_layout.addLayout(btn_layout)
        
        layout.addLayout(left_layout, 1) 
        layout.addLayout(right_layout, 2)

    def _load_diary_entries(self):
        self.diary_list.clear()
        entries = db_manager.get_diary_entries(self.user_id)
        
        if not entries:
            self.diary_list.addItem("Belum ada catatan.")
            return
            
        for entry in entries:
            entry_id, title_blob, content_blob, nonce, tag, timestamp = entry
            
            title_plain = crypto_utils.decrypt_aes_gcm(
                title_blob, self.master_key, nonce, tag
            )
            
            if title_plain:
                list_item = QListWidgetItem(f"{timestamp} - {title_plain}")
                list_item.setData(Qt.UserRole, entry) 
                self.diary_list.addItem(list_item)
            else:
                self.diary_list.addItem(f"{timestamp} - [Gagal Dekripsi Judul]")

    def _display_diary_entry(self, item):
        entry_data = item.data(Qt.UserRole)
        if not entry_data: return
            
        entry_id, title_blob, content_blob, nonce, tag, timestamp = entry_data
        self.current_entry_id = entry_id # Simpan ID untuk fungsi delete

        title_plain = crypto_utils.decrypt_aes_gcm(
            title_blob, self.master_key, nonce, tag
        )
        content_plain = crypto_utils.decrypt_aes_gcm(
            content_blob, self.master_key, nonce, tag
        )
        
        if title_plain is not None and content_plain is not None:
            self.diary_title.setText(title_plain)
            self.diary_content.setPlainText(content_plain)
            self.diary_title.setReadOnly(True) 
            self.diary_content.setReadOnly(True)
            self.save_btn.setText("Update Catatan") # Ganti teks tombol
            self.save_btn.clicked.disconnect()
            self.save_btn.clicked.connect(self._update_diary_entry)
        else:
            QMessageBox.critical(self, "Error", "Gagal mendekripsi catatan. Kunci salah atau data korup.")

    def _save_diary_entry(self):
        title = self.diary_title.text()
        content = self.diary_content.toPlainText()
        
        if not title or not content:
            QMessageBox.warning(self, "Error", "Judul dan Isi tidak boleh kosong.")
            return

        title_blob, nonce, tag = crypto_utils.encrypt_aes_gcm(title, self.master_key)
        content_blob, _, _ = crypto_utils.encrypt_aes_gcm(content, self.master_key) # Nonce-nya bakal beda, kita cuma ambil ciphertext
        
        # Kita menggunakan nonce dan tag dari enkripsi judul untuk keseluruhan entry.
        # Ini adalah penyederhanaan. Dalam aplikasi high-security, setiap bagian mungkin punya nonce/tag sendiri.
        success, msg = db_manager.save_diary_entry(self.user_id, title_blob, content_blob, nonce, tag)
        
        if success:
            QMessageBox.information(self, "Sukses", "Catatan berhasil dienkripsi dan disimpan.")
            self._load_diary_entries() 
            self._clear_diary_form()
        else:
            QMessageBox.critical(self, "Error", f"Gagal menyimpan: {msg}")

    def _update_diary_entry(self):
        title = self.diary_title.text()
        content = self.diary_content.toPlainText()
        
        if not title or not content:
            QMessageBox.warning(self, "Error", "Judul dan Isi tidak boleh kosong.")
            return

        if not hasattr(self, 'current_entry_id'):
            QMessageBox.warning(self, "Error", "Tidak ada catatan yang dipilih untuk diupdate.")
            return

        title_blob, nonce, tag = crypto_utils.encrypt_aes_gcm(title, self.master_key)
        content_blob, _, _ = crypto_utils.encrypt_aes_gcm(content, self.master_key)
        
        success, msg = db_manager.update_diary_entry(self.current_entry_id, title_blob, content_blob, nonce, tag)
        
        if success:
            QMessageBox.information(self, "Sukses", "Catatan berhasil diupdate.")
            self._load_diary_entries()
            self._clear_diary_form()
        else:
            QMessageBox.critical(self, "Error", f"Gagal mengupdate: {msg}")

    def _delete_diary_entry(self):
        if not hasattr(self, 'current_entry_id') or self.current_entry_id is None:
            QMessageBox.warning(self, "Peringatan", "Pilih catatan yang ingin dihapus terlebih dahulu.")
            return

        reply = QMessageBox.question(self, 'Konfirmasi Hapus', 
                                     "Anda yakin ingin menghapus catatan ini?", 
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            success, msg = db_manager.delete_diary_entry(self.current_entry_id)
            if success:
                QMessageBox.information(self, "Sukses", "Catatan berhasil dihapus.")
                self._load_diary_entries()
                self._clear_diary_form()
                self.current_entry_id = None # Reset ID
            else:
                QMessageBox.critical(self, "Error", f"Gagal menghapus: {msg}")


    def _clear_diary_form(self):
        self.diary_title.clear()
        self.diary_content.clear()
        self.diary_title.setReadOnly(False)
        self.diary_content.setReadOnly(False)
        self.diary_list.clearSelection()
        self.save_btn.setText("Simpan Catatan Baru")
        self.save_btn.clicked.disconnect()
        self.save_btn.clicked.connect(self._save_diary_entry)


class SuperTextWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<H3>Teks Super (Caesar + XOR)</H3>"))

        form_layout = QFormLayout()
        
        self.super_plain = QTextEdit()
        self.super_plain.setPlaceholderText("Tulis plaintext di sini...")
        self.super_cipher = QTextEdit()
        self.super_cipher.setPlaceholderText("Ciphertext akan muncul di sini (format bytes 'b\"...\")")
        self.super_shift = QLineEdit("3")
        self.super_shift.setValidator(QIntValidator()) # Hanya angka
        self.super_key = QLineEdit("kunci rahasia")
        
        form_layout.addRow(QLabel("Shift (Angka):"), self.super_shift)
        form_layout.addRow(QLabel("Kunci XOR (Teks):"), self.super_key)
        
        layout.addLayout(form_layout)
        layout.addWidget(QLabel("Plaintext:"))
        layout.addWidget(self.super_plain)
        
        btn_layout = QHBoxLayout()
        self.super_encrypt_btn = QPushButton("↓ Enkripsi ↓")
        self.super_encrypt_btn.setStyleSheet("background-color: #28a745; color: white;")
        self.super_encrypt_btn.clicked.connect(self._super_encrypt)
        btn_layout.addWidget(self.super_encrypt_btn)
        
        self.super_decrypt_btn = QPushButton("↑ Dekripsi ↑")
        self.super_decrypt_btn.setStyleSheet("background-color: #007bff; color: white;")
        self.super_decrypt_btn.clicked.connect(self._super_decrypt)
        btn_layout.addWidget(self.super_decrypt_btn)
        
        layout.addLayout(btn_layout)
        layout.addWidget(QLabel("Ciphertext (Hasil Enkripsi):"))
        layout.addWidget(self.super_cipher)

    def _get_super_params(self):
        try:
            shift = int(self.super_shift.text())
        except ValueError:
            QMessageBox.warning(self, "Error", "Shift harus berupa angka.")
            return None, None
        key = self.super_key.text()
        if not key:
            QMessageBox.warning(self, "Error", "Kunci XOR tidak boleh kosong.")
            return None, None
        return shift, key

    def _super_encrypt(self):
        shift, key = self._get_super_params()
        if shift is None: return
        
        plaintext = self.super_plain.toPlainText()
        if not plaintext:
            QMessageBox.warning(self, "Error", "Plaintext tidak boleh kosong.")
            return

        ciphertext_bytes = crypto_utils.encrypt_caesar_xor(plaintext, shift, key)
        
        if ciphertext_bytes:
            self.super_cipher.setPlainText(repr(ciphertext_bytes))

    def _super_decrypt(self):
        shift, key = self._get_super_params()
        if shift is None: return
        
        try:
            ciphertext_str = self.super_cipher.toPlainText()
            if not ciphertext_str.startswith("b'") or not ciphertext_str.endswith("'"):
                raise ValueError("Format ciphertext tidak valid.")
            ciphertext_bytes = eval(ciphertext_str) # Ini agak berisiko, tapi untuk demo gpp
            if not isinstance(ciphertext_bytes, bytes):
                raise TypeError
        except Exception:
            QMessageBox.warning(self, "Error", "Format ciphertext tidak valid. Harusnya b'...'")
            return
            
        plaintext = crypto_utils.decrypt_caesar_xor(ciphertext_bytes, shift, key)
        if plaintext is not None:
            self.super_plain.setPlainText(plaintext)
        else:
            QMessageBox.critical(self, "Dekripsi Gagal", "Kunci XOR atau Shift salah, atau data korup.")


class FileEncryptorWidget(QWidget):
    def __init__(self, master_key, parent=None):
        super().__init__(parent)
        self.master_key = master_key
        self._init_ui()
        self.selected_file_path = None

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.addWidget(QLabel("<H3>Enkripsi/Dekripsi File (Blowfish)</H3>"))
        
        self.file_path_label = QLabel("File belum dipilih.")
        layout.addWidget(self.file_path_label)
        
        self.file_select_btn = QPushButton("Pilih File...")
        self.file_select_btn.setStyleSheet("background-color: #17a2b8; color: white;")
        self.file_select_btn.clicked.connect(self._file_select)
        layout.addWidget(self.file_select_btn)
        
        self.file_encrypt_btn = QPushButton("Enkripsi File (Blowfish)")
        self.file_encrypt_btn.setStyleSheet("background-color: #28a745; color: white;")
        self.file_encrypt_btn.clicked.connect(self._file_encrypt)
        layout.addWidget(self.file_encrypt_btn)
        
        self.file_decrypt_btn = QPushButton("Dekripsi File (Blowfish)")
        self.file_decrypt_btn.setStyleSheet("background-color: #007bff; color: white;")
        self.file_decrypt_btn.clicked.connect(self._file_decrypt)
        layout.addWidget(self.file_decrypt_btn)
        
        layout.addStretch()

    def _file_select(self):
        filePath, _ = QFileDialog.getOpenFileName(self, "Pilih File", "")
        if filePath:
            self.selected_file_path = filePath
            self.file_path_label.setText(f"File: {os.path.basename(filePath)}")

    def _file_encrypt(self):
        if not self.selected_file_path:
            QMessageBox.warning(self, "Error", "Pilih file terlebih dahulu.")
            return
            
        output_path, _ = QFileDialog.getSaveFileName(self, "Simpan File Terenkripsi", self.selected_file_path + ".enc")
        if not output_path: return
        
        success, msg = crypto_utils.encrypt_file_blowfish(
            self.selected_file_path, self.master_key, output_path
        )
        QMessageBox.information(self, "Enkripsi File", msg)

    def _file_decrypt(self):
        if not self.selected_file_path:
            QMessageBox.warning(self, "Error", "Pilih file terenkripsi terlebih dahulu.")
            return
            
        output_path, _ = QFileDialog.getSaveFileName(self, "Simpan File Hasil Dekripsi", self.selected_file_path.replace(".enc", ".dec"))
        if not output_path: return
        
        success, msg = crypto_utils.decrypt_file_blowfish(
            self.selected_file_path, self.master_key, output_path
        )
        QMessageBox.information(self, "Dekripsi File", msg)


class SteganographyWidget(QWidget):
    def __init__(self, master_key, parent=None):
        super().__init__(parent)
        self.master_key = master_key
        self._init_ui()
        self.stego_cover_path = None

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.addWidget(QLabel("<H3>Steganografi (LSB) dengan AES</H3>"))
        
        self.stego_img_label = QLabel("Gambar Cover belum dipilih.")
        layout.addWidget(self.stego_img_label)
        
        self.stego_select_btn = QPushButton("Pilih Gambar Cover (PNG)...")
        self.stego_select_btn.setStyleSheet("background-color: #17a2b8; color: white;")
        self.stego_select_btn.clicked.connect(self._stego_select_cover)
        layout.addWidget(self.stego_select_btn)
        
        layout.addWidget(QLabel("Pesan Rahasia (Akan di-enkrip AES dulu):"))
        self.stego_payload = QTextEdit()
        self.stego_payload.setPlaceholderText("Tulis pesan rahasia di sini...")
        layout.addWidget(self.stego_payload)
        
        self.stego_embed_btn = QPushButton("Sembunyikan Pesan (Embed)")
        self.stego_embed_btn.setStyleSheet("background-color: #28a745; color: white;")
        self.stego_embed_btn.clicked.connect(self._stego_embed)
        layout.addWidget(self.stego_embed_btn)
        
        self.stego_extract_btn = QPushButton("Ekstrak Pesan (Extract)")
        self.stego_extract_btn.setStyleSheet("background-color: #007bff; color: white;")
        self.stego_extract_btn.clicked.connect(self._stego_extract)
        layout.addWidget(self.stego_extract_btn)
        
        layout.addStretch()

    def _stego_select_cover(self):
        filePath, _ = QFileDialog.getOpenFileName(self, "Pilih Gambar (PNG)", "", "PNG Files (*.png)")
        if filePath:
            self.stego_cover_path = filePath
            self.stego_img_label.setText(f"Gambar: {os.path.basename(filePath)}")

    def _stego_embed(self):
        if not self.stego_cover_path:
            QMessageBox.warning(self, "Error", "Pilih gambar cover PNG dulu.")
            return
        
        plaintext_payload = self.stego_payload.toPlainText()
        if not plaintext_payload:
            QMessageBox.warning(self, "Error", "Pesan rahasia tidak boleh kosong.")
            return

        output_path, _ = QFileDialog.getSaveFileName(self, "Simpan Stego-Image", "stego_output.png", "PNG Files (*.png)")
        if not output_path: return
        
        # 1. Enkrip dulu pesannya pake AES
        payload_bytes, nonce, tag = crypto_utils.encrypt_aes_gcm(plaintext_payload, self.master_key)
        
        # 2. Gabung (nonce + tag + ciphertext) jadi satu payload besar
        final_payload_bytes = nonce + tag + payload_bytes
        
        # 3. Sembunyikan (embed) payload besar ini
        success, msg = crypto_utils.embed_lsb(self.stego_cover_path, final_payload_bytes, output_path)
        QMessageBox.information(self, "Steganografi Embed", msg)

    def _stego_extract(self):
        if not self.stego_cover_path:
            QMessageBox.warning(self, "Error", "Pilih stego-image (gambar yg ada isinya) dulu.")
            return

        payload_bytes, msg = crypto_utils.extract_lsb(self.stego_cover_path)
        
        if not payload_bytes:
            QMessageBox.warning(self, "Ekstraksi Gagal", msg)
            return

        try:
            nonce = payload_bytes[0:16]      
            tag = payload_bytes[16:32]     
            ciphertext = payload_bytes[32:]  
            
            plaintext = crypto_utils.decrypt_aes_gcm(ciphertext, self.master_key, nonce, tag)
            
            if plaintext:
                self.stego_payload.setPlainText(plaintext)
                QMessageBox.information(self, "Ekstraksi Berhasil", "Pesan rahasia berhasil diekstrak.")
            else:
                QMessageBox.critical(self, "Ekstraksi Gagal", "Dekripsi gagal. Kunci master salah atau data korup.")
        except Exception as e:
            QMessageBox.critical(self, "Ekstraksi Error", f"Gagal membongkar payload: {e}. Mungkin ini bukan stego-image?")


class WelcomeWidget(QWidget):
    def __init__(self, username, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        
        welcome_label = QLabel(f"<h1>Selamat Datang, {username}!</h1>")
        welcome_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(welcome_label)

        info_label = QLabel("Ini adalah aplikasi Crypto Diary Anda. Pilih menu di samping untuk mulai menggunakan fitur kriptografi.")
        info_label.setAlignment(Qt.AlignCenter)
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        layout.addSpacing(50)

        # Tambahan: Quick Actions atau Info Statistik (Opsional)
        quick_actions_label = QLabel("<h3>Quick Actions:</h3>")
        quick_actions_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(quick_actions_label)

        action_layout = QHBoxLayout()
        action_layout.setAlignment(Qt.AlignCenter)

        # Contoh tombol Quick Action (nanti bisa dihubungkan ke fitur)
        self.new_diary_btn = QPushButton("Buat Catatan Baru")
        self.new_diary_btn.setStyleSheet("background-color: #28a745; color: white; padding: 10px; border-radius: 5px;")
        action_layout.addWidget(self.new_diary_btn)

        self.view_files_btn = QPushButton("Lihat File Enkripsi")
        self.view_files_btn.setStyleSheet("background-color: #17a2b8; color: white; padding: 10px; border-radius: 5px;")
        action_layout.addWidget(self.view_files_btn)

        layout.addLayout(action_layout)

        layout.addStretch() # Push everything to the top center

class SettingsWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        
        settings_label = QLabel("<h1>Pengaturan</h1>")
        settings_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(settings_label)

        self.dark_mode_toggle = QPushButton("Aktifkan Dark Mode")
        self.dark_mode_toggle.setCheckable(True)
        self.dark_mode_toggle.setStyleSheet("background-color: #6c757d; color: white; padding: 10px; border-radius: 5px;")
        layout.addWidget(self.dark_mode_toggle)

        layout.addStretch()


# --- Main Application Window ---

class MainWindow(QMainWindow):
    def __init__(self, user_id, master_key, username):
        super().__init__()
        
        self.user_id = user_id
        self.master_key = master_key
        self.username = username
        self.current_theme = 'light' # Default theme

        self.setWindowTitle('Crypto Diary - Menu Utama')
        self.setGeometry(100, 100, 1000, 700) # Ukuran window lebih besar
        
        self._init_ui()
        self._apply_theme('light') # Terapkan tema awal
        
    def _init_ui(self):
        # Container utama
        main_container = QWidget()
        self.setCentralWidget(main_container)
        
        main_layout = QHBoxLayout(main_container)
        main_layout.setContentsMargins(0, 0, 0, 0) # Hapus margin default

        # --- Side Navigation Bar ---
        self.nav_bar = QListWidget()
        self.nav_bar.setFixedWidth(200) # Lebar navigasi
        self.nav_bar.setStyleSheet("""
            QListWidget {
                background-color: #343a40; /* Dark background */
                color: #f8f9fa; /* Light text */
                border: none;
                font-size: 16px;
                padding: 10px 0;
            }
            QListWidget::item {
                padding: 15px 10px; /* Padding tiap item */
                border-bottom: 1px solid #495057; /* Garis pemisah */
            }
            QListWidget::item:selected {
                background-color: #007bff; /* Blue for selected */
                color: white;
                border-left: 5px solid #28a745; /* Green border for active */
            }
            QListWidget::item:hover {
                background-color: #495057; /* Darker on hover */
            }
        """)

        # Tambah item menu
        self.nav_bar.addItem(QListWidgetItem(QIcon("icons/home.png"), "Welcome")) # icon opsional
        self.nav_bar.addItem(QListWidgetItem(QIcon("icons/diary.png"), "Diary Pribadi"))
        self.nav_bar.addItem(QListWidgetItem(QIcon("icons/text.png"), "Teks Super"))
        self.nav_bar.addItem(QListWidgetItem(QIcon("icons/file.png"), "Enkripsi File"))
        self.nav_bar.addItem(QListWidgetItem(QIcon("icons/image.png"), "Steganografi"))
        self.nav_bar.addItem(QListWidgetItem(QIcon("icons/settings.png"), "Pengaturan"))
        
        self.nav_bar.currentRowChanged.connect(self._change_page)
        main_layout.addWidget(self.nav_bar)

        # --- Stacked Widget (Konten Utama) ---
        self.stacked_widget = QStackedWidget()
        main_layout.addWidget(self.stacked_widget)

        # Buat halaman-halaman (widget) untuk tiap menu
        self.welcome_page = WelcomeWidget(self.username)
        self.diary_page = DiaryTabWidget(self.user_id, self.master_key)
        self.super_text_page = SuperTextWidget()
        self.file_encryptor_page = FileEncryptorWidget(self.master_key)
        self.steganography_page = SteganographyWidget(self.master_key)
        self.settings_page = SettingsWidget() # Halaman pengaturan

        # Tambahkan ke stacked widget
        self.stacked_widget.addWidget(self.welcome_page) # Index 0
        self.stacked_widget.addWidget(self.diary_page)    # Index 1
        self.stacked_widget.addWidget(self.super_text_page) # Index 2
        self.stacked_widget.addWidget(self.file_encryptor_page) # Index 3
        self.stacked_widget.addWidget(self.steganography_page) # Index 4
        self.stacked_widget.addWidget(self.settings_page) # Index 5

        # Hubungkan tombol dark mode
        self.settings_page.dark_mode_toggle.clicked.connect(self._toggle_dark_mode)

        # Set halaman default
        self.nav_bar.setCurrentRow(0)

    def _change_page(self, index):
        self.stacked_widget.setCurrentIndex(index)

    def _toggle_dark_mode(self):
        if self.current_theme == 'light':
            self._apply_theme('dark')
            self.current_theme = 'dark'
            self.settings_page.dark_mode_toggle.setText("Nonaktifkan Dark Mode")
            self.settings_page.dark_mode_toggle.setStyleSheet("background-color: #6c757d; color: white; padding: 10px; border-radius: 5px;")
        else:
            self._apply_theme('light')
            self.current_theme = 'light'
            self.settings_page.dark_mode_toggle.setText("Aktifkan Dark Mode")
            self.settings_page.dark_mode_toggle.setStyleSheet("background-color: #6c757d; color: white; padding: 10px; border-radius: 5px;")


    def _apply_theme(self, theme_name):
        palette = QPalette()
        if theme_name == 'dark':
            palette.setColor(QPalette.Window, QColor(53, 53, 53))
            palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
            palette.setColor(QPalette.Base, QColor(25, 25, 25))
            palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
            palette.setColor(QPalette.ToolTipBase, QColor(255, 255, 255))
            palette.setColor(QPalette.ToolTipText, QColor(255, 255, 255))
            palette.setColor(QPalette.Text, QColor(255, 255, 255))
            palette.setColor(QPalette.Button, QColor(53, 53, 53))
            palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
            palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
            palette.setColor(QPalette.Link, QColor(42, 130, 218))
            palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
            palette.setColor(QPalette.HighlightedText, QColor(0, 0, 0))
            self.setStyleSheet("""
                QMainWindow { background-color: #343a40; }
                QWidget { color: white; }
                QLineEdit, QTextEdit, QListWidget { 
                    background-color: #495057; 
                    border: 1px solid #6c757d; 
                    color: white; 
                }
                QMessageBox { 
                    background-color: #495057; 
                    color: white; 
                }
                QMessageBox QLabel { color: white; }
                QMessageBox QPushButton { 
                    background-color: #007bff; 
                    color: white; 
                    border: none; 
                    padding: 5px 10px; 
                    border-radius: 3px; 
                }
            """)
        else: # Light theme
            palette = QApplication.instance().palette() # Reset ke palette default
            self.setStyleSheet("") # Clear custom stylesheet
            # Set colors for specific elements
            palette.setColor(QPalette.Window, QColor(240, 240, 240))
            palette.setColor(QPalette.WindowText, QColor(0, 0, 0))
            palette.setColor(QPalette.Base, QColor(255, 255, 255))
            palette.setColor(QPalette.AlternateBase, QColor(230, 230, 230))
            palette.setColor(QPalette.Text, QColor(0, 0, 0))
            palette.setColor(QPalette.Button, QColor(240, 240, 240))
            palette.setColor(QPalette.ButtonText, QColor(0, 0, 0))
            palette.setColor(QPalette.Highlight, QColor(0, 120, 215))
            palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
            self.setStyleSheet("""
                QLineEdit, QTextEdit, QListWidget { 
                    background-color: white; 
                    border: 1px solid #ccc; 
                    color: black; 
                }
            """)

        QApplication.instance().setPalette(palette)