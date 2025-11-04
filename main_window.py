import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QStackedWidget, QLabel, QLineEdit,
                             QPushButton, QTextEdit, QListWidget, QFileDialog,
                             QMessageBox, QInputDialog, QListWidgetItem,
                             QFormLayout, QToolBar, QAction, QToolButton,
                             QComboBox) # <--- PASTIKAN INI ADA
from PyQt5.QtGui import QIcon, QPalette, QColor, QIntValidator
from PyQt5.QtCore import Qt, QSize, pyqtSignal # <--- PASTIKAN pyqtSignal ADA
import os
from translations import STRINGS # <--- IMPORT INI
import db_manager
import crypto_utils

# --- Sub-Widget untuk Tiap Fitur (biar rapi) ---

# --- Sub-Widget untuk Tiap Fitur (biar rapi) ---

# --- Sub-Widget untuk Tiap Fitur (biar rapi) ---

# GANTI SEMUA 'class DiaryTabWidget' DI main_window.py DENGAN INI:

class DiaryTabWidget(QWidget):
    def __init__(self, user_id, master_key, username, parent=None):
        super().__init__(parent)
        self.user_id = user_id
        self.master_key = master_key
        self.username = username
        self.current_entry_id = None # Buat nyimpen ID yg lagi diedit
        self._init_ui()
        self._load_diary_entries()

    def _init_ui(self):
        # INI _init_ui YANG BENER (nggak pake setCentralWidget)
        layout = QHBoxLayout(self) # Langsung set layout ke 'self' (QWidget)
        
        # Kolom Kiri: List Judul
        left_layout = QVBoxLayout()
        self.diary_list_label = QLabel("<H3>Catatan Terenkripsi:</H3>")
        left_layout.addWidget(self.diary_list_label)
        self.diary_list = QListWidget()
        self.diary_list.itemClicked.connect(self._display_diary_entry)
        left_layout.addWidget(self.diary_list)
        
        # Kolom Kanan: Editor Teks
        right_layout = QVBoxLayout()
        self.diary_title_label = QLabel("<H3>Judul Catatan:</H3>")
        right_layout.addWidget(self.diary_title_label)
        self.diary_title = QLineEdit()
        self.diary_title.setPlaceholderText("Masukkan judul catatan Anda...")
        right_layout.addWidget(self.diary_title)
        
        self.diary_content_label = QLabel("<H3>Isi Catatan:</H3>")
        right_layout.addWidget(self.diary_content_label)
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
        
    # PASTE SEMUA BLOK INI DI DALAM 'class MainWindow' (setelah _init_ui)

    def _handle_nav_click(self, item):
        """
        FIX 1: Ini fungsi yang ilang & nyebabin crash.
        Fungsi ini nanganin SEMUA klik di sidebar.
        """
        # Dapatkan teks dari item (misal "Logout" atau "Diary Pribadi")
        item_text = item.text()
        
        # Dapatkan teks "Logout" yang sudah diterjemahkan
        logout_text = STRINGS[self.current_lang]['nav_logout']
        
        if item_text == logout_text:
            self._do_logout()
        else:
            # Kalo bukan logout, ganti halaman
            row = self.nav_bar.row(item)
            if row < self.stacked_widget.count(): # Cek biar valid
                self.stacked_widget.setCurrentIndex(row)

    def _change_page(self, index):
        """
        Fungsi ini cuma buat ganti page.
        (Sebenernya ini udah nggak kepake kalo kita pake _handle_nav_click, 
        tapi biarin aja aman)
        """
        if index < self.stacked_widget.count():
            self.stacked_widget.setCurrentIndex(index)

    def _do_logout(self):
        """
        FIX 2: Ini fungsi logout yang UDAH BENER (pake terjemahan)
        """
        # Ambil teks terjemahan
        title = STRINGS[self.current_lang]['confirm_logout']
        msg = STRINGS[self.current_lang]['confirm_logout_msg']
        
        reply = QMessageBox.question(self, title, msg, 
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.logout_signal.emit() # Kirim signal ke main.py
            self.close() # Tutup Main Window

    def _on_language_change(self, lang_code):
        """
        FIX 3: Ini fungsi yang ilang buat nerima signal ganti bahasa.
        Ini yang ngebenerin bug 'Welcome' & 'Settings' kosong.
        """
        print(f"MAIN: Bahasa diganti ke: {lang_code}") # Debug
        self.current_lang = lang_code
        self.retranslate_ui(lang_code) # Update teks di MainWindow
        
        # Update teks di semua child widget
        self.welcome_page.retranslate_ui(lang_code)
        self.settings_page.retranslate_ui(lang_code, self.current_theme == 'dark')
        # (Nanti lu bisa tambahin retranslate_ui() buat tab lain di sini)

    def retranslate_ui(self, lang_code):
        """
        FIX 4: Ini fungsi yang ilang buat nerjemahin UI.
        Ini juga ngebenerin bug 'Welcome' & 'Settings' kosong.
        """
        # Nerjemahin Navigasi Bar
        self.nav_bar.item(0).setText(STRINGS[lang_code]['nav_welcome'])
        self.nav_bar.item(1).setText(STRINGS[lang_code]['nav_diary'])
        self.nav_bar.item(2).setText(STRINGS[lang_code]['nav_super_text'])
        self.nav_bar.item(3).setText(STRINGS[lang_code]['nav_file_encrypt'])
        self.nav_bar.item(4).setText(STRINGS[lang_code]['nav_stegano'])
        self.nav_bar.item(5).setText(STRINGS[lang_code]['nav_settings'])
        # Index 7 karena index 6 itu spacer
        self.nav_bar.item(7).setText(STRINGS[lang_code]['nav_logout'])

    def retranslate_ui(self, lang_code):
        strings = STRINGS[lang_code]
        self.diary_list_label.setText(strings['diary_title']) # Asumsi ada di translations
        self.diary_title_label.setText(strings['diary_note_title'])
        self.diary_content_label.setText(strings['diary_note_content'])
        self.diary_title.setPlaceholderText(strings['diary_placeholder_title'])
        self.diary_content.setPlaceholderText(strings['diary_placeholder_content'])
        self.save_btn.setText(strings['diary_btn_save'])
        self.clear_btn.setText(strings['diary_btn_clear'])
        self.delete_btn.setText(strings['diary_btn_delete'])
        
        # Panggil ulang _load_diary_entries() agar list juga ikut ter-update
        self._load_diary_entries()

    def _toggle_dark_mode(self):
        """
        FIX 5: Ini fungsi toggle dark mode yang UDAH BENER
        """
        # Cek status tombolnya SEKARANG
        is_dark_toggled_on = self.settings_page.dark_mode_toggle.isChecked()
        
        if is_dark_toggled_on:
            self._apply_theme('dark')
            self.current_theme = 'dark'
        else:
            self._apply_theme('light')
            self.current_theme = 'light'
        
        # Update teks tombolnya pake bahasa yg bener
        self.settings_page.retranslate_ui(self.current_lang, is_dark_toggled_on)
        
    def _load_diary_entries(self):
        self.diary_list.clear()
        entries = db_manager.get_diary_entries(self.user_id)
        
        if not entries:
            self.diary_list.addItem("Belum ada catatan.")
            return
            
        for entry in entries:
            entry_id, title_blob, content_blob, nonce, tag, timestamp = entry
            
            (title_plain, _) = crypto_utils.decrypt_aes_gcm_entry(
                title_blob, content_blob, self.master_key, nonce, tag
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

        (title_plain, content_plain) = crypto_utils.decrypt_aes_gcm_entry(
            title_blob, content_blob, self.master_key, nonce, tag
        )
        
        if title_plain is not None and content_plain is not None:
            self.diary_title.setText(title_plain)
            self.diary_content.setPlainText(content_plain)
            
            # --- FIX BUG 1: Bikin dia bisa diedit ---
            self.diary_title.setReadOnly(False) 
            self.diary_content.setReadOnly(False)
            # ----------------------------------------
            
            self.save_btn.setText("Update Catatan") # Ganti teks tombol
            
            # Hati-hati, disconnect semua koneksi dulu biar nggak numpuk
            try: self.save_btn.clicked.disconnect() 
            except TypeError: pass # Kalo belom ada koneksi, diemin aja
            
            self.save_btn.clicked.connect(self._update_diary_entry)
        else:
            QMessageBox.critical(self, "Error", "Gagal mendekripsi catatan. Kunci salah atau data korup.")

    def _save_diary_entry(self):
        title = self.diary_title.text()
        content = self.diary_content.toPlainText()
        
        if not title or not content:
            QMessageBox.warning(self, "Error", "Judul dan Isi tidak boleh kosong.")
            return

        # Pake fungsi enkrip yg udah bener
        (title_blob, content_blob, nonce, tag) = crypto_utils.encrypt_aes_gcm_entry(
            title, content, self.master_key)

        if title_blob is not None:
            success, msg = db_manager.save_diary_entry(
                self.user_id, title_blob, content_blob, nonce, tag)
        else:
            success, msg = False, "Enkripsi AES Gagal"
        
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

        if not hasattr(self, 'current_entry_id') or self.current_entry_id is None:
            QMessageBox.warning(self, "Error", "Tidak ada catatan yang dipilih untuk diupdate.")
            return

        (title_blob, content_blob, nonce, tag) = crypto_utils.encrypt_aes_gcm_entry(
            title, content, self.master_key
        )

        if title_blob is not None:
            success, msg = db_manager.update_diary_entry(
                self.current_entry_id, title_blob, content_blob, nonce, tag
            )
        else:
            success, msg = False, "Enkripsi AES Gagal"
        
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
            else:
                QMessageBox.critical(self, "Error", f"Gagal menghapus: {msg}")

    def _clear_diary_form(self):
        self.diary_title.clear()
        self.diary_content.clear()
        self.diary_title.setReadOnly(False)
        self.diary_content.setReadOnly(False)
        self.diary_list.clearSelection()
        self.save_btn.setText("Simpan Catatan Baru")
        
        # Hati-hati, disconnect semua koneksi dulu biar nggak numpuk
        try: self.save_btn.clicked.disconnect() 
        except TypeError: pass # Kalo belom ada koneksi, diemin aja
        self.save_btn.clicked.connect(self._save_diary_entry)
        
        self.current_entry_id = None # FIX BUG 3


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
            self.super_cipher.setPlainText(ciphertext_bytes.hex()) # Ubah jadi string hex

    def _super_decrypt(self):
        shift, key = self._get_super_params()
        if shift is None: return
        
        try:
          ciphertext_str = self.super_cipher.toPlainText()
          ciphertext_bytes = bytes.fromhex(ciphertext_str) # Ubah dari string hex
        except ValueError:
          QMessageBox.warning(self, "Error", "Format ciphertext tidak valid. Harusnya string hex.")
          return
        except Exception as e:
          QMessageBox.warning(self, "Error", f"Error: {e}")
          return
            
        plaintext = crypto_utils.decrypt_caesar_xor(ciphertext_bytes, shift, key)
        if plaintext is not None:
            self.super_plain.setPlainText(plaintext)
        else:
            QMessageBox.critical(self, "Dekripsi Gagal", "Kunci XOR atau Shift salah, atau data korup.")
    def retranslate_ui(self, lang_code):
        strings = STRINGS[lang_code]
        self.layout().itemAt(0).widget().setText(strings['super_title'])
        self.super_shift.setPlaceholderText(strings['super_shift_ph'])
        self.super_key.setPlaceholderText(strings['super_key_ph'])
        self.super_plain.setPlaceholderText(strings['super_plain_ph'])
        self.super_cipher.setPlaceholderText(strings['super_cipher_ph'])
        self.super_encrypt_btn.setText(strings['super_btn_encrypt'])
        self.super_decrypt_btn.setText(strings['super_btn_decrypt'])


class FileEncryptorWidget(QWidget):
    def __init__(self, master_key, username, parent=None): # <-- Tambah username
        super().__init__(parent)
        self.master_key = master_key
        self.username = username # <-- Tambah ini
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
            
        default_name = os.path.basename(self.selected_file_path)
        output_path, _ = QFileDialog.getSaveFileName(self, "Simpan File Terenkripsi", default_name)
        if not output_path: return
        
        success, msg = crypto_utils.encrypt_file_blowfish(
            self.selected_file_path, self.master_key, output_path
        )
        QMessageBox.information(self, "Enkripsi File", msg)

    def _file_decrypt(self):
        if not self.selected_file_path:
            QMessageBox.warning(self, "Error", "Pilih file terenkripsi terlebih dahulu.")
            return
        base_name = os.path.basename(self.selected_file_path)
        default_name, _ = os.path.splitext(base_name)
        output_path, _ = QFileDialog.getSaveFileName(self, "Simpan File Hasil Dekripsi", default_name)
        if not output_path: return
        
        success, msg = crypto_utils.decrypt_file_blowfish(
            self.selected_file_path, self.master_key, output_path
        )
        QMessageBox.information(self, "Dekripsi File", msg)
    
    def retranslate_ui(self, lang_code):
        strings = STRINGS[lang_code]
        self.layout().itemAt(0).widget().setText(strings['file_title'])
        self.file_path_label.setText(strings['file_not_selected'])
        self.file_select_btn.setText(strings['file_btn_select'])
        self.file_encrypt_btn.setText(strings['file_btn_encrypt'])
        self.file_decrypt_btn.setText(strings['file_btn_decrypt'])


class SteganographyWidget(QWidget):
    def __init__(self, master_key, username, parent=None): # <-- Tambah username
        super().__init__(parent)
        self.master_key = master_key
        self.username = username # <-- Tambah ini
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
        payload_bytes, nonce, tag = crypto_utils.encrypt_aes_gcm_single(plaintext_payload, self.master_key)
        
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
            
            plaintext = crypto_utils.decrypt_aes_gcm_single(ciphertext, self.master_key, nonce, tag)
            
            if plaintext:
                self.stego_payload.setPlainText(plaintext)
                QMessageBox.information(self, "Ekstraksi Berhasil", "Pesan rahasia berhasil diekstrak.")
            else:
                QMessageBox.critical(self, "Ekstraksi Gagal", "Dekripsi gagal. Kunci master salah atau data korup.")
        except Exception as e:
            QMessageBox.critical(self, "Ekstraksi Error", f"Gagal membongkar payload: {e}. Mungkin ini bukan stego-image?")
    
    def retranslate_ui(self, lang_code):
        strings = STRINGS[lang_code]
        self.layout().itemAt(0).widget().setText(strings['stego_title'])
        self.stego_img_label.setText(strings['stego_cover_not_selected'])
        self.stego_select_btn.setText(strings['stego_btn_select_cover'])
        self.layout().itemAt(3).widget().setText(strings['stego_msg_label']) # Label Pesan Rahasia
        self.stego_payload.setPlaceholderText(strings['stego_payload_ph'])
        self.stego_embed_btn.setText(strings['stego_btn_embed'])
        self.stego_extract_btn.setText(strings['stego_btn_extract'])


# GANTI SEMUA 'class WelcomeWidget' DENGAN INI:

# GANTI SEMUA 'class WelcomeWidget' DENGAN INI:

class WelcomeWidget(QWidget):
    def __init__(self, username, parent=None):
        super().__init__(parent)
        self.username = username
        self._init_ui() # Panggil _init_ui dulu

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)

        # Ganti Teks Statis jadi Variabel Class
        self.welcome_label = QLabel()
        self.welcome_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.welcome_label)

        self.info_label = QLabel()
        self.info_label.setAlignment(Qt.AlignCenter)
        self.info_label.setWordWrap(True)
        layout.addWidget(self.info_label)

        layout.addSpacing(50)

        self.quick_actions_label = QLabel()
        self.quick_actions_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.quick_actions_label)

        action_layout = QHBoxLayout()
        action_layout.setAlignment(Qt.AlignCenter)

        self.new_diary_btn = QPushButton()
        self.new_diary_btn.setStyleSheet("background-color: #28a745; color: white; padding: 10px; border-radius: 5px;")
        action_layout.addWidget(self.new_diary_btn)

        self.view_files_btn = QPushButton()
        self.view_files_btn.setStyleSheet("background-color: #17a2b8; color: white; padding: 10px; border-radius: 5px;")
        action_layout.addWidget(self.view_files_btn)

        layout.addLayout(action_layout)
        layout.addStretch()

    def retranslate_ui(self, lang_code):
        """Fungsi BARU untuk update teks"""
        self.welcome_label.setText(STRINGS[lang_code]['welcome_greeting'].format(username=self.username))
        self.info_label.setText(STRINGS[lang_code]['welcome_info'])
        self.quick_actions_label.setText(STRINGS[lang_code]['welcome_quick_actions'])
        self.new_diary_btn.setText(STRINGS[lang_code]['welcome_btn_new_note'])
        self.view_files_btn.setText(STRINGS[lang_code]['welcome_btn_view_files'])

# GANTI SEMUA 'class SettingsWidget' DENGAN INI:

class SettingsWidget(QWidget):
    language_changed = pyqtSignal(str) # Signal untuk kirim bahasa baru

    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui() # Panggil _init_ui

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignTop | Qt.AlignHCenter) # Ubah alignment
        layout.setSpacing(20)
        layout.setContentsMargins(20, 20, 20, 20) # Kasih padding

        self.title_label = QLabel()
        self.title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.title_label)

        # --- Dark Mode ---
        self.dark_mode_toggle = QPushButton()
        self.dark_mode_toggle.setCheckable(True)
        self.dark_mode_toggle.setStyleSheet("background-color: #6c757d; color: white; padding: 10px; border-radius: 5px;")
        layout.addWidget(self.dark_mode_toggle)

        layout.addSpacing(20) # Spacer

        # --- Language Selector ---
        self.lang_label = QLabel()
        self.lang_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.lang_label)

        self.lang_combo = QComboBox()
        self.lang_combo.addItem("Bahasa Indonesia", 'id') # Teks display, data
        self.lang_combo.addItem("English", 'en')
        # Pake 'activated' biar nggak ke-trigger pas init
        self.lang_combo.activated[str].connect(self._on_lang_change)
        layout.addWidget(self.lang_combo)
        # --------------------------

        layout.addStretch()

    def _on_lang_change(self, text_display):
        """Fungsi BARU: Kirim signal pas combo box diganti"""
        lang_code = self.lang_combo.currentData()
        print(f"Bahasa diganti ke: {lang_code}") # Debug
        self.language_changed.emit(lang_code)

    def retranslate_ui(self, lang_code, is_dark):
        """Fungsi BARU untuk update teks"""
        self.title_label.setText(STRINGS[lang_code]['settings_title'])
        self.lang_label.setText(STRINGS[lang_code]['settings_lang_label'])

        # Update teks tombol dark mode
        if is_dark:
            self.dark_mode_toggle.setText(STRINGS[lang_code]['settings_dark_mode_off'])
        else:
            self.dark_mode_toggle.setText(STRINGS[lang_code]['settings_dark_mode_on'])

# GANTI FUNGSI __init__ DI MAINWINDOW (line 524) DENGAN INI:

# --- Main Application Window ---

# --- Main Application Window ---

class MainWindow(QMainWindow):
    logout_signal = pyqtSignal()

    def __init__(self, user_id, master_key, username):
        super().__init__()

        self.user_id = user_id
        self.master_key = master_key
        self.username = username
        self.current_lang = 'id' # Default bahasa
        self.current_theme = 'light' # Default theme

        self.setWindowTitle('Crypto Diary - Menu Utama')
        self.setGeometry(100, 100, 1000, 700)

        self._init_ui() # Panggil _init_ui SATU KALI
        self._apply_theme('light') # Terapkan tema awal
        
        # Panggil _on_language_change di akhir __init__
        # Ini yang nge-fix bug tulisan kosong di Welcome & Settings
        self._on_language_change(self.current_lang) 


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
                background-color: #343a40;
                color: #f8f9fa; 
                border: none;
                font-size: 16px;
                padding: 10px 0;
            }
            QListWidget::item {
                padding: 15px 10px;
                border-bottom: 1px solid #495057;
            }
            QListWidget::item:selected {
                background-color: #007bff;
                color: white;
                border-left: 5px solid #28a745;
            }
            QListWidget::item:hover {
                background-color: #495057;
            }
        """)

        # Tambah item menu
        self.nav_bar.addItem(QListWidgetItem(QIcon("icons/home.png"), "Welcome")) # Index 0
        self.nav_bar.addItem(QListWidgetItem(QIcon("icons/diary.png"), "Diary Pribadi")) # Index 1
        self.nav_bar.addItem(QListWidgetItem(QIcon("icons/text.png"), "Teks Super")) # Index 2
        self.nav_bar.addItem(QListWidgetItem(QIcon("icons/file.png"), "Enkripsi File")) # Index 3
        self.nav_bar.addItem(QListWidgetItem(QIcon("icons/image.png"), "Steganografi")) # Index 4
        self.nav_bar.addItem(QListWidgetItem(QIcon("icons/settings.png"), "Pengaturan")) # Index 5

        # FIX BUG 'addStretch'
        spacer_item = QListWidgetItem()
        spacer_item.setFlags(spacer_item.flags() & ~Qt.ItemIsSelectable & ~Qt.ItemIsEnabled)
        self.nav_bar.addItem(spacer_item) # Spacer (Index 6)

        logout_item = QListWidgetItem(QIcon("icons/logout.png"), "Logout") # Index 7
        logout_item.setForeground(QColor("#dc3545")) 
        self.nav_bar.addItem(logout_item)

        # Sambungin signal 'itemClicked' (CRITICAL LINE)
        self.nav_bar.itemClicked.connect(self._handle_nav_click)
        main_layout.addWidget(self.nav_bar)

        # --- Stacked Widget (Konten Utama) ---
        self.stacked_widget = QStackedWidget()
        main_layout.addWidget(self.stacked_widget)

        # Buat halaman-halaman (widget) untuk tiap menu
        self.welcome_page = WelcomeWidget(self.username)
        # Tambah username ke widget-widget ini
        self.diary_page = DiaryTabWidget(self.user_id, self.master_key, self.username)
        self.super_text_page = SuperTextWidget()
        self.file_encryptor_page = FileEncryptorWidget(self.master_key, self.username)
        self.steganography_page = SteganographyWidget(self.master_key, self.username)
        self.settings_page = SettingsWidget() 

        # Tambahkan ke stacked widget
        self.stacked_widget.addWidget(self.welcome_page) # Index 0
        self.stacked_widget.addWidget(self.diary_page)    # Index 1
        self.stacked_widget.addWidget(self.super_text_page) # Index 2
        self.stacked_widget.addWidget(self.file_encryptor_page) # Index 3
        self.stacked_widget.addWidget(self.steganography_page) # Index 4
        self.stacked_widget.addWidget(self.settings_page) # Index 5

        # --- Sambungin Signal Fitur Baru ---
        self.settings_page.dark_mode_toggle.clicked.connect(self._toggle_dark_mode)
        self.settings_page.language_changed.connect(self._on_language_change)

        self.welcome_page.new_diary_btn.clicked.connect(
            lambda: self.nav_bar.setCurrentRow(1)
        )
        self.welcome_page.view_files_btn.clicked.connect(
            lambda: self.nav_bar.setCurrentRow(3)
        )

        # Set halaman default
        self.nav_bar.setCurrentRow(0)

    # --- FUNGSI NAVIGASI DAN LOGOUT ---

    def _handle_nav_click(self, item):
        """
        FIX CRASH: Ini fungsi yang dicaru Python.
        Fungsi ini nanganin SEMUA klik di sidebar.
        """
        item_text = item.text()
        
        # Dapatkan teks "Logout" yang sudah diterjemahkan
        logout_text = STRINGS[self.current_lang]['nav_logout']
        
        if item_text == logout_text:
            self._do_logout()
        else:
            # Kalo bukan logout, ganti halaman
            row = self.nav_bar.row(item)
            if row < self.stacked_widget.count():
                self.stacked_widget.setCurrentIndex(row)

    def _do_logout(self):
        """
        FIX LOGOUT: Fungsi untuk memproses permintaan logout.
        """
        # Ambil teks terjemahan
        title = STRINGS[self.current_lang]['confirm_logout']
        msg = STRINGS[self.current_lang]['confirm_logout_msg']

        reply = QMessageBox.question(self, title, msg, 
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.logout_signal.emit() # Kirim signal ke main.py
            self.close() 

    # --- FUNGSI TRANSLATION ---

    def _on_language_change(self, lang_code):
        """
        FIX TRANSLATION: Dipanggil pas signal ganti bahasa.
        """
        self.current_lang = lang_code
        self.retranslate_ui(lang_code) # Update teks di MainWindow
        
        # Update teks di semua child widget (Penting!)
        self.welcome_page.retranslate_ui(lang_code)
        self.settings_page.retranslate_ui(lang_code, self.current_theme == 'dark')
        self.diary_page.retranslate_ui(lang_code)
        self.super_text_page.retranslate_ui(lang_code)
        self.file_encryptor_page.retranslate_ui(lang_code)
        self.steganography_page.retranslate_ui(lang_code)


    def retranslate_ui(self, lang_code):
        """
        FIX UI: Update semua teks di Navigasi Bar.
        """
        self.nav_bar.item(0).setText(STRINGS[lang_code]['nav_welcome'])
        self.nav_bar.item(1).setText(STRINGS[lang_code]['nav_diary'])
        self.nav_bar.item(2).setText(STRINGS[lang_code]['nav_super_text'])
        self.nav_bar.item(3).setText(STRINGS[lang_code]['nav_file_encrypt'])
        self.nav_bar.item(4).setText(STRINGS[lang_code]['nav_stegano'])
        self.nav_bar.item(5).setText(STRINGS[lang_code]['nav_settings'])
        self.nav_bar.item(7).setText(STRINGS[lang_code]['nav_logout']) # Index 7 krn index 6 itu spacer

    # --- FUNGSI THEME ---

    def _toggle_dark_mode(self):
        """
        FIX THEME: Memproses toggle dark/light mode.
        """
        is_dark_toggled_on = self.settings_page.dark_mode_toggle.isChecked()
        
        if is_dark_toggled_on:
            self._apply_theme('dark')
            self.current_theme = 'dark'
        else:
            self._apply_theme('light')
            self.current_theme = 'light'
        
        # Update teks tombol di Settings
        self.settings_page.retranslate_ui(self.current_lang, is_dark_toggled_on)
        
        
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

def _on_language_change(self, lang_code):
    """Dipanggil pas signal dari SettingsWidget keterima"""
    print(f"MAIN: Bahasa diganti ke: {lang_code}") # Debug
    self.current_lang = lang_code
    self.retranslate_ui(lang_code) # Update teks di MainWindow

    # Update teks di semua child widget
    self.welcome_page.retranslate_ui(lang_code)
    self.settings_page.retranslate_ui(lang_code, self.current_theme == 'dark')
    # (Tambahin retranslate_ui() buat tab lain kalo lu mau)

def retranslate_ui(self, lang_code):
    """Update semua teks di MainWindow (terutama nav_bar)"""
    self.nav_bar.item(0).setText(STRINGS[lang_code]['nav_welcome'])
    self.nav_bar.item(1).setText(STRINGS[lang_code]['nav_diary'])
    self.nav_bar.item(2).setText(STRINGS[lang_code]['nav_super_text'])
    self.nav_bar.item(3).setText(STRINGS[lang_code]['nav_file_encrypt'])
    self.nav_bar.item(4).setText(STRINGS[lang_code]['nav_stegano'])
    self.nav_bar.item(5).setText(STRINGS[lang_code]['nav_settings'])
    self.nav_bar.item(7).setText(STRINGS[lang_code]['nav_logout']) # Index 7 krn ada spacer

# GANTI FUNGSI _do_logout (line 649) DENGAN INI (biar pake teks terjemahan):

def _do_logout(self):
    # Ambil teks terjemahan
    title = STRINGS[self.current_lang]['confirm_logout']
    msg = STRINGS[self.current_lang]['confirm_logout_msg']

    reply = QMessageBox.question(self, title, msg, 
                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
    if reply == QMessageBox.Yes:
        self.logout_signal.emit() # Kirim signal
        self.close() # Tutup Main Window

# GANTI FUNGSI _toggle_dark_mode (line 658) DENGAN INI (biar teks tombol ikut ganti):

def _toggle_dark_mode(self):
    is_dark_toggled_on = self.settings_page.dark_mode_toggle.isChecked()

    if is_dark_toggled_on:
        self._apply_theme('dark')
        self.current_theme = 'dark'
    else:
        self._apply_theme('light')
        self.current_theme = 'light'

    # Update teks tombol di Settings
    self.settings_page.retranslate_ui(self.current_lang, is_dark_toggled_on)
        
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
        spacer_item = QListWidgetItem()
        spacer_item.setFlags(spacer_item.flags() & ~Qt.ItemIsSelectable & ~Qt.ItemIsEnabled)
        self.nav_bar.addItem(spacer_item) # Spacer (Index 6)
        logout_item = QListWidgetItem(QIcon("icons/logout.png"), "Logout")
        logout_item.setForeground(QColor("#dc3545")) # Bikin warnanya merah
        self.nav_bar.addItem(logout_item)
        
        self.nav_bar.currentRowChanged.connect(self._change_page)
        self.nav_bar.itemClicked.connect(self._handle_nav_click)
        main_layout.addWidget(self.nav_bar)

        # --- Stacked Widget (Konten Utama) ---
        self.stacked_widget = QStackedWidget()
        main_layout.addWidget(self.stacked_widget)

        # Buat halaman-halaman (widget) untuk tiap menu
        # Buat halaman-halaman (widget) untuk tiap menu
        self.welcome_page = WelcomeWidget(self.username)

        # --- FIX DI SINI ---
        self.diary_page = DiaryTabWidget(self.user_id, self.master_key, self.username)
        self.super_text_page = SuperTextWidget() # (Widget ini gak butuh info sesi)
        self.file_encryptor_page = FileEncryptorWidget(self.master_key, self.username)
        self.steganography_page = SteganographyWidget(self.master_key, self.username)
        # --------------------

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
        self.welcome_page.new_diary_btn.clicked.connect(
            lambda: self.nav_bar.setCurrentRow(1) # Pindah ke tab Diary (index 1)
        )
        self.welcome_page.view_files_btn.clicked.connect(
            lambda: self.nav_bar.setCurrentRow(3) # Pindah ke tab File (index 3)
        )

        # Set halaman default
        self.nav_bar.setCurrentRow(0)

    # PASTE SEMUA BLOK INI DI DALAM 'class MainWindow' (setelah _init_ui)

    def _handle_nav_click(self, item):
        """
        FIX 1: Ini fungsi yang ilang & nyebabin crash.
        Fungsi ini nanganin SEMUA klik di sidebar.
        """
        # Dapatkan teks dari item (misal "Logout" atau "Diary Pribadi")
        item_text = item.text()
        
        # Dapatkan teks "Logout" yang sudah diterjemahkan
        logout_text = STRINGS[self.current_lang]['nav_logout']
        
        if item_text == logout_text:
            self._do_logout()
        else:
            # Kalo bukan logout, ganti halaman
            row = self.nav_bar.row(item)
            if row < self.stacked_widget.count(): # Cek biar valid (bukan spacer)
                self.stacked_widget.setCurrentIndex(row)

    def _change_page(self, index):
        """
        Fungsi ini cuma buat ganti page.
        (Sebenernya ini udah nggak kepake kalo kita pake _handle_nav_click, 
        tapi biarin aja aman)
        """
        if index < self.stacked_widget.count():
            self.stacked_widget.setCurrentIndex(index)

    def _do_logout(self):
        """
        FIX 2: Ini fungsi logout yang UDAH BENER (pake terjemahan)
        """
        # Ambil teks terjemahan
        title = STRINGS[self.current_lang]['confirm_logout']
        msg = STRINGS[self.current_lang]['confirm_logout_msg']
        
        reply = QMessageBox.question(self, title, msg, 
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.logout_signal.emit() # Kirim signal ke main.py
            self.close() # Tutup Main Window

    def _on_language_change(self, lang_code):
        """
        FIX 3: Ini fungsi yang ilang buat nerima signal ganti bahasa.
        Ini yang ngebenerin bug 'Welcome' & 'Settings' kosong.
        """
        print(f"MAIN: Bahasa diganti ke: {lang_code}") # Debug
        self.current_lang = lang_code
        self.retranslate_ui(lang_code) # Update teks di MainWindow
        
        # Update teks di semua child widget
        self.welcome_page.retranslate_ui(lang_code)
        self.settings_page.retranslate_ui(lang_code, self.current_theme == 'dark')
        # (Nanti lu bisa tambahin retranslate_ui() buat tab lain di sini)

    def retranslate_ui(self, lang_code):
        """
        FIX 4: Ini fungsi yang ilang buat nerjemahin UI.
        Ini juga ngebenerin bug 'Welcome' & 'Settings' kosong.
        """
        # Nerjemahin Navigasi Bar
        self.nav_bar.item(0).setText(STRINGS[lang_code]['nav_welcome'])
        self.nav_bar.item(1).setText(STRINGS[lang_code]['nav_diary'])
        self.nav_bar.item(2).setText(STRINGS[lang_code]['nav_super_text'])
        self.nav_bar.item(3).setText(STRINGS[lang_code]['nav_file_encrypt'])
        self.nav_bar.item(4).setText(STRINGS[lang_code]['nav_stegano'])
        self.nav_bar.item(5).setText(STRINGS[lang_code]['nav_settings'])
        # Index 7 karena index 6 itu spacer
        self.nav_bar.item(7).setText(STRINGS[lang_code]['nav_logout'])

    def _toggle_dark_mode(self):
        """
        FIX 5: Ini fungsi toggle dark mode yang UDAH BENER
        """
        # Cek status tombolnya SEKARANG
        is_dark_toggled_on = self.settings_page.dark_mode_toggle.isChecked()
        
        if is_dark_toggled_on:
            self._apply_theme('dark')
            self.current_theme = 'dark'
        else:
            self._apply_theme('light')
            self.current_theme = 'light'
        
        # Update teks tombolnya pake bahasa yg bener
        self.settings_page.retranslate_ui(self.current_lang, is_dark_toggled_on)
    
    def _handle_nav_click(self, item):
        text = item.text()

    # Cek apakah item punya teks terjemahan
        logout_text = STRINGS[self.current_lang]['nav_logout']

        if text == logout_text:
            self._do_logout()
        else:
        # Dapatkan index dari item yg diklik (selain logout)
            row = self.nav_bar.row(item)

            if row < self.stacked_widget.count(): # Pastikan bukan spacer (kalo ada)
                self.stacked_widget.setCurrentIndex(row)    

    def _change_page(self, index):
    # Fungsi ini sekarang cuma buat ganti page
    # Cek biar 'logout' (index terakhir) nggak ganti page
        if index < self.stacked_widget.count():
            self.stacked_widget.setCurrentIndex(index)

    def _do_logout(self):
        reply = QMessageBox.question(self, 'Konfirmasi Logout', 
                                 "Anda yakin ingin logout?", 
                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.logout_signal.emit() # Kirim signal
            self.close() # Tutup Main Window

    def _toggle_dark_mode(self):
        is_dark = self.current_theme == 'light'
        
        if is_dark:
            self._apply_theme('dark')
            self.current_theme = 'dark'
        else:
            self._apply_theme('light')
            self.current_theme = 'light'
        
        self.settings_page.retranslate_ui(self.current_lang, is_dark)


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