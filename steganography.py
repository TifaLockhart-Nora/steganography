# -*- coding: utf-8 -*-
from cryptography.fernet import Fernet, InvalidToken
from PyQt5.QtCore import Qt
from PIL import Image
from cryptography.fernet import Fernet
from PyQt5.QtGui import (
    QIcon,
    QPixmap,
    QPalette,
    QBrush,
    )
import os
import sys
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QMainWindow,
    QVBoxLayout,
    QPushButton,
    QFileDialog,
    QLabel,
    QLineEdit,
    QGridLayout,
    QTextEdit,
    QMessageBox,
    QTabWidget,
    QAction,
    QMenu,
)



        
class SteganographyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("My Steganography")  # Set the window title
        
        # Get the path to the resource directory
        if getattr(sys, 'frozen', False):
            # The application is frozen (i.e., it's running as a bundled .exe file)
            resource_dir = os.path.join(sys._MEIPASS, 'src')
        else:
            # The application is not frozen (i.e., it's running as a Python script)
            resource_dir = 'src'
        # Get the path to the background image
        
        window_ico_path = os.path.join(resource_dir, 'window.ico')
        bg_image_path = os.path.abspath(os.path.join(resource_dir, 'Winbg.png')).replace('\\', '/')
        
        
        icon = QIcon(f'{window_ico_path}')
        self.setWindowIcon(icon)
        self.setFixedSize(400, 400)
        # self.setStyleSheet(f"background-image: url('{bg_image_path}')")
        with open("style.css", "r") as f:
            stylesheet = f.read()
        app.setStyleSheet(stylesheet)
        
        pixmap = QPixmap(f"{bg_image_path}")
        pixmap = pixmap.scaled(self.width(), self.height())
        palette = QPalette()
        palette.setBrush(QPalette.Background, QBrush(pixmap))
        self.setPalette(palette)
        
        menubar = self.menuBar()
        fileMenu = QMenu('File', self)
        menubar.addMenu(fileMenu)

        openFile = QAction('Open', self)
        openFile.triggered.connect(self.open_file)  # 连接 triggered 信号到 open_file 槽函数
        fileMenu.addAction(openFile)
        
        fileMenu = QMenu('About', self)
        menubar.addMenu(fileMenu)

        about = QAction('Help', self)
        about.triggered.connect(self.open_file)  # 连接 triggered 信号到 open_file 槽函数
        fileMenu.addAction(about)
        
        self.initUI()
        
    def open_file(self):
        print("open")
        
    def encrypt_init(self):
        self.tab_encrypt.layout = QGridLayout(self.tab_encrypt)
        # self.tab_encrypt.layout.setSpacing(10)  # Set the spacing to 10 pixels
        self.browse_entry = QLineEdit(self)
        self.browse_button = QPushButton("Browse", self)
        self.browse_button.clicked.connect(self.browse_file_path)
        self.tab_encrypt.layout.addWidget(self.browse_entry, 0, 0, 1, 2)
        self.tab_encrypt.layout.addWidget(self.browse_button, 0, 2, 1, 1)

        self.save_entry = QLineEdit(self)
        self.save_button = QPushButton("Save", self)
        self.save_button.clicked.connect(self.save_file_path)
        self.tab_encrypt.layout.addWidget(self.save_entry, 1, 0, 1, 2)
        self.tab_encrypt.layout.addWidget(self.save_button, 1, 2, 1, 1)

        self.text_to_encrypt = QTextEdit(self)
        # self.tab_encrypt.layout.addWidget(QLabel("Text to hide:"), 1, 0,5,2)
        self.tab_encrypt.layout.addWidget(self.text_to_encrypt, 2, 0, 1, 3)

        self.encrypt_button = QPushButton("Start encryption", self)
        self.encrypt_button.clicked.connect(self.encrypt_and_hide)
        self.tab_encrypt.layout.addWidget(self.encrypt_button, 3, 0, 1, 3)

        self.key_entry = QLineEdit(self)
        self.key_entry.setReadOnly(True)
        self.tab_encrypt.layout.addWidget(QLabel("Generated Key:"), 4, 0, 1, 1)
        self.tab_encrypt.layout.addWidget(self.key_entry, 4, 1, 1, 2)

        self.tab_encrypt.setLayout(self.tab_encrypt.layout)

    def decrypt_init(self):
        self.tab_decrypt.layout = QGridLayout(self.tab_decrypt)

        self.decrypt_entry = QLineEdit(self)
        self.open_button = QPushButton("Open", self)
        self.open_button.clicked.connect(self.open_file_path)
        self.tab_decrypt.layout.addWidget(self.decrypt_entry, 0, 0, 1, 2)
        self.tab_decrypt.layout.addWidget(self.open_button, 0, 2, 1, 1)

        self.key_display = QLineEdit(self)
        self.tab_decrypt.layout.addWidget(QLabel("Extract Key:"), 1, 0, 1, 1)
        self.tab_decrypt.layout.addWidget(self.key_display, 1, 1, 1, 2)

        self.decrypted_text = QTextEdit(self)
        # self.decrypted_text.setReadOnly(False)
        self.tab_decrypt.layout.addWidget(QLabel("Decrypted Text:"), 2, 0, 1, 1)
        self.tab_decrypt.layout.addWidget(self.decrypted_text, 3, 0, 1, 3)

        self.decrypt_button = QPushButton("Start decrypting", self)
        self.decrypt_button.clicked.connect(self.extract_and_decrypt)
        self.clear_button = QPushButton("Clear", self)
        self.clear_button.clicked.connect((lambda: self.decrypted_text.clear()))

        self.tab_decrypt.layout.addWidget(self.decrypt_button, 4, 0, 1, 2)
        self.tab_decrypt.layout.addWidget(self.clear_button, 4, 2, 1, 1)
        # self.tab_decrypt.setLayout(self.tab_decrypt.layout)

    def initUI(self):
        self.layout = QVBoxLayout()
        
        # Initialize tab screen
        self.tabs = QTabWidget()
        self.tab_encrypt = QWidget()
        self.tab_decrypt = QWidget()
        # self.tabs.resize(800, 480)

        self.tabs.addTab(self.tab_encrypt, "Encrypt")
        self.tabs.addTab(self.tab_decrypt, "Decrypt")
        self.encrypt_init()
        self.decrypt_init()
        self.layout.addWidget(self.tabs)
        
        centralWidget = QWidget()
        centralWidget.setLayout(self.layout)
        # Set the central widget of QMainWindow
        self.setCentralWidget(centralWidget)

    def hide_text(self, image_path, text):
        img = Image.open(image_path)
        binary_text = format(len(text), "016b") + "".join(
            format(i, "08b") for i in text
        )
        data_index = 0

        for values in img.getdata():
            pixel = list(values)
            for index in range(3):  # RGB
                if data_index < len(binary_text):
                    pixel[index] = pixel[index] & ~1 | int(binary_text[data_index])
                    data_index += 1
            yield tuple(pixel)

    def extract_text(self, image_path):
        img = Image.open(image_path)
        binary_text = ""

        for values in img.getdata():
            pixel = list(values)
            for index in range(3):  # RGB
                binary_text += str(pixel[index] & 1)
        text_length = int(binary_text[:16], 2)
        return bytes(
            int(binary_text[i : i + 8], 2) for i in range(16, 16 + text_length * 8, 8)
        ).decode()

    def browse_file_path(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        options |= QFileDialog.DontUseNativeDialog
        image_path, _ = QFileDialog.getOpenFileName(
            self, "Open Image File", "", "Images (*.png)", options=options
        )
        if image_path:
            self.browse_entry.setText(image_path)

    def save_file_path(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        hidden_image_path, _ = QFileDialog.getSaveFileName(
            self, "Save Image File", "", "Images (*.png)", options=options
        )
        if hidden_image_path:  # Check if the path is not empty
            if not hidden_image_path.endswith(".png"):
                hidden_image_path += ".png"
            self.save_entry.setText(hidden_image_path)

    def encrypt_and_hide(self):
        image_path = self.browse_entry.text()
        hidden_image_path = self.save_entry.text()
        text_to_hide = self.text_to_encrypt.toPlainText()

        if not text_to_hide:
            QMessageBox.critical(self, "Error", "Please enter text to encrypt.")
            return

        if not image_path or not os.path.exists(image_path):
            QMessageBox.critical(
                self, "Error", "The encrypted image is invalid or empty."
            )
            return

        directory = os.path.dirname(hidden_image_path)
        print("directory = ",directory)
        if not hidden_image_path or not os.path.exists(directory):
            QMessageBox.critical(
                self, "Error", "The path to save the image is invalid or empty."
            )
            return

        encryption_key = Fernet.generate_key()
        cipher_suite = Fernet(encryption_key)
        cipher_text = cipher_suite.encrypt(text_to_hide.encode())

        image = Image.open(image_path)
        image.putdata(list(self.hide_text(image_path, cipher_text)))
        image.save(hidden_image_path, "PNG", quality=100)

        self.key_entry.setText(encryption_key.decode())

    def open_file_path(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        options |= QFileDialog.DontUseNativeDialog
        image_path, _ = QFileDialog.getOpenFileName(
            self, "Open Image File", "", "Images (*.png)", options=options
        )
        if image_path:
            self.decrypt_entry.setText(image_path)

    def extract_and_decrypt(self):
        key = self.key_display.text().encode()
        image_path = self.decrypt_entry.text()

        if not key:
            QMessageBox.critical(self, "Error", "The key is empty.")
            return

        if not image_path:
            QMessageBox.critical(
                self, "Error", "No file selected to decrypt the image."
            )
            return

        try:
            cipher_suite = Fernet(key)
            cipher_text = self.extract_text(image_path)
            extracted_text = cipher_suite.decrypt(cipher_text).decode()
        except InvalidToken:
            QMessageBox.critical(self, "Error", "Invalid key or token.")
            return
        except Exception as e:   #REVIEW - python3.8会报错,python3.10不会
            print("error = ", str(e))
            QMessageBox.critical(self, "Error", str(e))
            return
        self.decrypted_text.setPlainText(extracted_text)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = SteganographyApp()
    ex.show()
    sys.exit(app.exec_())
