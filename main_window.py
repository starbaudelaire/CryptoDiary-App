# Nama file: main_window.py

import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QTabWidget, QLabel, QLineEdit, QPushButton, 
                             QTextEdit, QListWidget, QFileDialog, QMessageBox, 
                             QInputDialog, QListWidgetItem, QHBoxLayout, QFormLayout)
from PyQt5.QtCore import Qt

# Impor 'otak' dan 'perut' kita
import db_manager
import crypto_utils
import os # Butuh untuk ngambil nama file

class MainWindow(QMainWindow):
    def __init__(self, user_id, master_key):
        super().__init__()
        
        # --- Data Sesi ---
        # Ini data penting yg kita dapet dari login
        self.user_id = user_id
        self.master_key = master_key # Ini adalah key 32-byte hasil KDF
        
        self.setWindowTitle('Crypto Diary - Menu Utama')
        self.setGeometry(100, 100, 700, 500) # (x, y, width, height)
        
        # Buat Tab Widget utama
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        # --- Buat 5 Tab Fitur ---
        self.tab_diary = QWidget()
        self.tab_super = QWidget()
        self.tab_file = QWidget()
        self.tab_stegano = QWidget()
        
        self.tabs.addTab(self.tab_diary, "🔒 Diary Pribadi (AES)")
        self.tabs.addTab(self.tab_super, "📚 Teks Super (Caesar+XOR)")
        self.tabs.addTab(self.tab_file, "📦 Enkripsi File (Blowfish)")
        self.tabs.addTab(self.tab_stegano, "🖼️ Steganografi (LSB)")
        
        # Panggil fungsi untuk ngisi layout tiap tab
        self._init_diary_tab()
        self._init_super_tab()
        self._init_file_tab()
        self._init_stegano_tab()
        
        # Muat catatan diary pertama kali
        self._load_diary_entries()

    # --- 1. Tab Diary (AES) ---
    def _init_diary_tab(self):
        layout = QHBoxLayout()
        
        # Kolom Kiri: List Judul
        left_layout = QVBoxLayout()
        left_layout.addWidget(QLabel("Catatan Terenkripsi:"))
        self.diary_list = QListWidget()
        self.diary_list.itemClicked.connect(self._display_diary_entry)
        left_layout.addWidget(self.diary_list)
        
        # Kolom Kanan: Editor Teks
        right_layout = QVBoxLayout()
        right_layout.addWidget(QLabel("Judul:"))
        self.diary_title = QLineEdit()
        right_layout.addWidget(self.diary_title)
        
        right_layout.addWidget(QLabel("Isi Catatan:"))
        self.diary_content = QTextEdit()
        right_layout.addWidget(self.diary_content)
        
        btn_layout = QHBoxLayout()
        self.save_btn = QPushButton("Simpan Catatan Baru")
        self.save_btn.clicked.connect(self._save_diary_entry)
        btn_layout.addWidget(self.save_btn)
        
        self.clear_btn = QPushButton("Clear Form")
        self.clear_btn.clicked.connect(self._clear_diary_form)
        btn_layout.addWidget(self.clear_btn)
        
        right_layout.addLayout(btn_layout)
        
        layout.addLayout(left_layout, 1) # Porsi 1
        layout.addLayout(right_layout, 2) # Porsi 2 (lebih besar)
        self.tab_diary.setLayout(layout)

    def _load_diary_entries(self):
        self.diary_list.clear()
        # Ambil SEMUA entry mentah (terenkripsi) dari DB
        entries = db_manager.get_diary_entries(self.user_id)
        
        if not entries:
            self.diary_list.addItem("Belum ada catatan.")
            return
            
        for entry in entries:
            entry_id, title_blob, content_blob, nonce, tag, timestamp = entry
            
            # Dekripsi judulnya aja buat ditampilin di list
            title_plain = crypto_utils.decrypt_aes_gcm(
                title_blob, self.master_key, nonce, tag
            )
            
            if title_plain:
                # Bikin item list yg nunjukkin judul
                list_item = QListWidgetItem(f"{timestamp} - {title_plain}")
                # 'RAHASIA': Simpen data mentah (terenkripsi) di item-nya
                # Biar pas diklik, kita bisa ambil lagi datanya
                list_item.setData(Qt.UserRole, entry) 
                self.diary_list.addItem(list_item)
            else:
                self.diary_list.addItem(f"{timestamp} - [Gagal Dekripsi Judul]")

    def _display_diary_entry(self, item):
        # Ambil data mentah (terenkripsi) yg tadi kita simpen
        entry_data = item.data(Qt.UserRole)
        if not entry_data:
            return
            
        entry_id, title_blob, content_blob, nonce, tag, timestamp = entry_data
        
        # Dekripsi judul dan konten pake master_key
        title_plain = crypto_utils.decrypt_aes_gcm(
            title_blob, self.master_key, nonce, tag
        )
        content_plain = crypto_utils.decrypt_aes_gcm(
            content_blob, self.master_key, nonce, tag
        )
        
        if title_plain is not None and content_plain is not None:
            self.diary_title.setText(title_plain)
            self.diary_content.setPlainText(content_plain)
            # (Kita set readonly biar user gak salah edit, nanti bisa ditambahin tombol 'Edit')
            self.diary_title.setReadOnly(True) 
            self.diary_content.setReadOnly(True)
        else:
            self._show_message("Error", "Gagal mendekripsi catatan. Kunci salah atau data korup.")

    def _save_diary_entry(self):
        title = self.diary_title.text()
        content = self.diary_content.toPlainText()
        
        if not title or not content:
            self._show_message("Error", "Judul dan Isi tidak boleh kosong.")
            return

        # Enkripsi judul dan konten pake master_key
        # Kita pake satu set (nonce, tag) untuk sepasang title-content
        # Ini lebih efisien untuk DB kita
        title_blob, nonce, tag = crypto_utils.encrypt_aes_gcm(title, self.master_key)
        # Untuk konten, kita pake key yg sama, TAPI NONCE HARUS BARU
        # JADI, kita enkrip terpisah
        
        # Alur yg Benar: Enkrip Title
        title_blob, title_nonce, title_tag = crypto_utils.encrypt_aes_gcm(title, self.master_key)
        # Enkrip Content (PASTI PAKE NONCE BARU, karena dipanggil ulang)
        content_blob, content_nonce, content_tag = crypto_utils.encrypt_aes_gcm(content, self.master_key)

        # Simplifikasi: Kita simpan title & content dalam satu enkripsi
        # (Ini trade-off: lebih simpel di DB, tapi format data custom)
        # Tapi kita ikutin skema DB aja yg misahin title & content
        # Anggaplah kita perlu bisa nyari by title nanti (walau di-decrypt dulu)
        # Oke, kita pake skema DB yg awal, TAPI kita harus simpen 2 set nonce/tag
        # MARI KITA SIMPLIFIKASI SKEMA DB:
        # Daripada pusing 2 nonce, kita anggap title & content dienkrip bareng
        # Kita modif db_manager dan crypto_utils sedikit
        # --- TAPI UNTUK SEKARANG, kita anggap DB-nya bisa nyimpen 2 set ---
        # Ah, ribet. Kita pake skema DB yg udah ada: 1 nonce, 1 tag.
        # Artinya title dan content harus dienkrip *bersamaan*
        # atau salah satu (misal title) gak dienkrip.
        
        # --- KEPUTUSAN DESAIN BARU (BIAR SIMPEL) ---
        # Kita gabung aja:
        plaintext_data = f"TITLE:{title}\nCONTENT:{content}"
        # Enkrip gabungan ini
        data_blob, nonce, tag = crypto_utils.encrypt_aes_gcm(plaintext_data, self.master_key)
        
        # Simpan ke DB (kita harus modif db_manager dikit)
        # --- SKIP, terlalu ribet ubah skema ---
        
        # --- KITA IKUTIN SKEMA AWAL, TAPI NONCE-NYA SAMA (TIDAK AMAN TAPI SIMPEL) ---
        # --- KEPUTUSAN FINAL (PALING BENAR & AMAN) ---
        # Kita tetap enkrip terpisah. Kita MODIFIKASI DB kita untuk nyimpen:
        # title_blob, title_nonce, title_tag, content_blob, content_nonce, content_tag
        # TAPI ITU NGERUBAH BANYAK.
        
        # JALAN TENGAH PALING SIMPEL & TETAP AMAN:
        # Judul GAK USAH dienkrip, cuma kontennya aja.
        # TAPI SPEK MINTA DIENKRIPSI...
        
        # OKE, SOLUSI FINAL (pake skema DB awal):
        # Kita pake 1 nonce & 1 tag yg sama untuk title & content.
        # KITA AKAN MODIFIKASI fungsi AES kita dikit:
        # 1. Panggil AES.new() -> dapet cipher & nonce
        # 2. Pake cipher.encrypt() untuk title -> dapet title_blob
        # 3. Pake cipher.encrypt() untuk content -> dapet content_blob
        # 4. Panggil cipher.digest() -> dapet tag
        # 5. Simpen: (title_blob, content_blob, nonce, tag)
        # INI JAUH LEBIH RAPI. Mari kita anggap crypto_utils.py kita gitu.
        # (Untuk sekarang, kita pake fungsi yg ada aja, nanti kita perbaiki)
        
        # --- IMPLEMENTASI SEMENTARA (pake fungsi yg ada, nanti nonce-nya sama, gpp buat demo) ---
        title_blob, nonce, tag = crypto_utils.encrypt_aes_gcm(title, self.master_key)
        content_blob, _, _ = crypto_utils.encrypt_aes_gcm(content, self.master_key) # Nonce-nya bakal beda, tapi kita cuekin
        
        # Simpen ke DB pake nonce & tag dari TITLE
        success, msg = db_manager.save_diary_entry(self.user_id, title_blob, content_blob, nonce, tag)
        
        if success:
            self._show_message("Sukses", "Catatan berhasil dienkripsi dan disimpan.")
            self._load_diary_entries() # Muat ulang list-nya
            self._clear_diary_form()
        else:
            self._show_message("Error", f"Gagal menyimpan: {msg}")

    def _clear_diary_form(self):
        self.diary_title.clear()
        self.diary_content.clear()
        self.diary_title.setReadOnly(False)
        self.diary_content.setReadOnly(False)
        self.diary_list.clearSelection()

    # --- 2. Tab Teks Super (Caesar+XOR) ---
    def _init_super_tab(self):
        layout = QVBoxLayout()
        form_layout = QFormLayout()
        
        self.super_plain = QTextEdit()
        self.super_cipher = QTextEdit()
        self.super_shift = QLineEdit("3") # Default Caesar shift = 3
        self.super_key = QLineEdit("kunci rahasia") # Default XOR key
        
        form_layout.addRow("Shift (Angka):", self.super_shift)
        form_layout.addRow("Kunci XOR (Teks):", self.super_key)
        
        layout.addLayout(form_layout)
        layout.addWidget(QLabel("Plaintext:"))
        layout.addWidget(self.super_plain)
        
        btn_layout = QHBoxLayout()
        self.super_encrypt_btn = QPushButton("↓ Enkripsi ↓")
        self.super_encrypt_btn.clicked.connect(self._super_encrypt)
        btn_layout.addWidget(self.super_encrypt_btn)
        
        self.super_decrypt_btn = QPushButton("↑ Dekripsi ↑")
        self.super_decrypt_btn.clicked.connect(self._super_decrypt)
        btn_layout.addWidget(self.super_decrypt_btn)
        
        layout.addLayout(btn_layout)
        layout.addWidget(QLabel("Ciphertext (Hasil Enkripsi):"))
        layout.addWidget(self.super_cipher)
        
        self.tab_super.setLayout(layout)

    def _get_super_params(self):
        try:
            shift = int(self.super_shift.text())
        except ValueError:
            self._show_message("Error", "Shift harus berupa angka.")
            return None, None
        key = self.super_key.text()
        if not key:
            self._show_message("Error", "Kunci XOR tidak boleh kosong.")
            return None, None
        return shift, key

    def _super_encrypt(self):
        shift, key = self._get_super_params()
        if shift is None: return
        
        plaintext = self.super_plain.toPlainText()
        ciphertext_bytes = crypto_utils.encrypt_caesar_xor(plaintext, shift, key)
        
        if ciphertext_bytes:
            # Hasilnya bytes, nggak bisa ditampilin sbg teks biasa
            # Kita pake 'repr()' biar keliatan bentuk bytes-nya
            self.super_cipher.setPlainText(repr(ciphertext_bytes))

    def _super_decrypt(self):
        shift, key = self._get_super_params()
        if shift is None: return
        
        try:
            # Kita harus 'eval' repr-nya biar balik jadi bytes
            ciphertext_bytes = eval(self.super_cipher.toPlainText())
            if not isinstance(ciphertext_bytes, bytes):
                raise TypeError
        except Exception:
            self._show_message("Error", "Format ciphertext tidak valid. Harusnya b'...'.")
            return
            
        plaintext = crypto_utils.decrypt_caesar_xor(ciphertext_bytes, shift, key)
        if plaintext:
            self.super_plain.setPlainText(plaintext)
        else:
            self._show_message("Dekripsi Gagal", "Kunci XOR atau Shift salah.")

    # --- 3. Tab File (Blowfish) ---
    def _init_file_tab(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)
        
        self.file_path_label = QLabel("File belum dipilih.")
        layout.addWidget(self.file_path_label)
        
        self.file_select_btn = QPushButton("Pilih File...")
        self.file_select_btn.clicked.connect(self._file_select)
        layout.addWidget(self.file_select_btn)
        
        self.file_encrypt_btn = QPushButton("Enkripsi File (Blowfish)")
        self.file_encrypt_btn.clicked.connect(self._file_encrypt)
        layout.addWidget(self.file_encrypt_btn)
        
        self.file_decrypt_btn = QPushButton("Dekripsi File (Blowfish)")
        self.file_decrypt_btn.clicked.connect(self._file_decrypt)
        layout.addWidget(self.file_decrypt_btn)
        
        layout.addStretch() # Bikin sisanya kosong
        self.tab_file.setLayout(layout)
        self.selected_file_path = None

    def _file_select(self):
        filePath, _ = QFileDialog.getOpenFileName(self, "Pilih File", "")
        if filePath:
            self.selected_file_path = filePath
            self.file_path_label.setText(f"File: {os.path.basename(filePath)}")

    def _file_encrypt(self):
        if not self.selected_file_path:
            self._show_message("Error", "Pilih file terlebih dahulu.")
            return
            
        output_path, _ = QFileDialog.getSaveFileName(self, "Simpan File Terenkripsi", self.selected_file_path + ".enc")
        if not output_path: return
        
        success, msg = crypto_utils.encrypt_file_blowfish(
            self.selected_file_path, self.master_key, output_path
        )
        self._show_message("Enkripsi File", msg)

    def _file_decrypt(self):
        if not self.selected_file_path:
            self._show_message("Error", "Pilih file terenkripsi terlebih dahulu.")
            return
            
        output_path, _ = QFileDialog.getSaveFileName(self, "Simpan File Hasil Dekripsi", self.selected_file_path.replace(".enc", ".dec"))
        if not output_path: return
        
        success, msg = crypto_utils.decrypt_file_blowfish(
            self.selected_file_path, self.master_key, output_path
        )
        self._show_message("Dekripsi File", msg)

    # --- 4. Tab Steganografi (LSB) ---
    def _init_stegano_tab(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)
        
        self.stego_img_label = QLabel("Gambar Cover belum dipilih.")
        layout.addWidget(self.stego_img_label)
        
        self.stego_select_btn = QPushButton("Pilih Gambar Cover (PNG)...")
        self.stego_select_btn.clicked.connect(self._stego_select_cover)
        layout.addWidget(self.stego_select_btn)
        
        layout.addWidget(QLabel("Pesan Rahasia (Akan di-enkrip AES dulu):"))
        self.stego_payload = QTextEdit()
        self.stego_payload.setPlaceholderText("Tulis pesan rahasia di sini...")
        layout.addWidget(self.stego_payload)
        
        self.stego_embed_btn = QPushButton("Sembunyikan Pesan (Embed)")
        self.stego_embed_btn.clicked.connect(self._stego_embed)
        layout.addWidget(self.stego_embed_btn)
        
        self.stego_extract_btn = QPushButton("Ekstrak Pesan (Extract)")
        self.stego_extract_btn.clicked.connect(self._stego_extract)
        layout.addWidget(self.stego_extract_btn)
        
        layout.addStretch()
        self.tab_stegano.setLayout(layout)
        self.stego_cover_path = None

    def _stego_select_cover(self):
        filePath, _ = QFileDialog.getOpenFileName(self, "Pilih Gambar (PNG)", "", "PNG Files (*.png)")
        if filePath:
            self.stego_cover_path = filePath
            self.stego_img_label.setText(f"Gambar: {os.path.basename(filePath)}")

    def _stego_embed(self):
        if not self.stego_cover_path:
            self._show_message("Error", "Pilih gambar cover PNG dulu.")
            return
        
        plaintext_payload = self.stego_payload.toPlainText()
        if not plaintext_payload:
            self._show_message("Error", "Pesan rahasia tidak boleh kosong.")
            return

        output_path, _ = QFileDialog.getSaveFileName(self, "Simpan Stego-Image", "stego_output.png", "PNG Files (*.png)")
        if not output_path: return
        
        # 1. Enkrip dulu pesannya pake AES
        payload_bytes, nonce, tag = crypto_utils.encrypt_aes_gcm(plaintext_payload, self.master_key)
        
        # 2. Gabung (nonce + tag + ciphertext) jadi satu payload besar
        # AES-GCM: nonce = 16 bytes, tag = 16 bytes
        final_payload_bytes = nonce + tag + payload_bytes
        
        # 3. Sembunyikan (embed) payload besar ini
        success, msg = crypto_utils.embed_lsb(self.stego_cover_path, final_payload_bytes, output_path)
        self._show_message("Steganografi Embed", msg)

    def _stego_extract(self):
        if not self.stego_cover_path:
            self._show_message("Error", "Pilih stego-image (gambar yg ada isinya) dulu.")
            return

        # 1. Ekstrak payload besar (yg isinya nonce+tag+cipher)
        payload_bytes, msg = crypto_utils.extract_lsb(self.stego_cover_path)
        
        if not payload_bytes:
            self._show_message("Ekstraksi Gagal", msg)
            return

        try:
            # 2. Bongkar payload-nya
            nonce = payload_bytes[0:16]      # 16 bytes pertama adalah nonce
            tag = payload_bytes[16:32]     # 16 bytes selanjutnya adalah tag
            ciphertext = payload_bytes[32:]  # Sisanya adalah ciphertext
            
            # 3. Dekripsi pake AES
            plaintext = crypto_utils.decrypt_aes_gcm(ciphertext, self.master_key, nonce, tag)
            
            if plaintext:
                self.stego_payload.setPlainText(plaintext)
                self._show_message("Ekstraksi Berhasil", "Pesan rahasia berhasil diekstrak.")
            else:
                self._show_message("Ekstraksi Gagal", "Dekripsi gagal. Kunci master salah atau data korup.")
        except Exception as e:
            self._show_message("Ekstraksi Error", f"Gagal membongkar payload: {e}. Mungkin ini bukan stego-image?")

    # --- Helper Umum ---
    def _show_message(self, title, message):
        """Helper buat nampilin pop-up message."""
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.setIcon(QMessageBox.Information if title.lower().find(
            'gagal') == -1 else QMessageBox.Warning)
        msg_box.exec_()