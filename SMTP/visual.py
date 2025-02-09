from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QStackedWidget, QVBoxLayout, QWidget, QPushButton, QAbstractScrollArea,
    QLineEdit, QTextEdit, QLabel, QTableWidget, QTableWidgetItem, QHBoxLayout, QCheckBox
)
from PyQt6 import QtCore
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
import sys
import re, time
import asyncio
import threading
from cliente import authentication, send_email, retrieve_messages

class SMTPClientUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cliente SMTP")
        self.setGeometry(100, 100, 1000, 800)
        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)

        # Configuración por defecto del servidor SMTP
        self.smtp_server = "127.0.0.1"
        self.smtp_port = 2525

        # Estilo general
        self.setStyleSheet("""
            QMainWindow {
                background-color: #000000;
            }
            QWidget {
                background-color: #000000;
                color: white;
            }
            QPushButton {
                background-color: #4b0082;
                color: white;
                border: 1px solid #4b0082;
                border-radius: 3px;
                padding: 5px;
                font-size: 14px;
                min-width: 200px;
                max-width: 200px;
            }
            QPushButton:hover {
                background-color: #660099;
            }
            QLabel {
                color: white;
                font-size: 16px;
            }
            QLineEdit, QTextEdit {
                background-color: #000000;
                color: white;
                border: 1px solid #660099;
                border-radius: 3px;
                padding: 10px;
                font-size: 16px;
            }
            QTableWidget {
                background-color: #000000;
                color: white;
                border: 1px solid #660099;
            }
            QTableWidget::item {
                border: 1px solid #660099;
            }
        """)

        self.create_login_screen()
        self.create_menu_screen()
        self.create_send_email_screen()
        self.create_inbox_screen()
        self.create_server_config_screen()

        self.stacked_widget.setCurrentWidget(self.login_screen)

    def create_login_screen(self):
        self.login_screen = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        login_label = QLabel("Inicio de sesión")
        login_label.setFont(QFont("Roboto", 20, QFont.Weight.Bold))
        layout.addWidget(login_label, alignment=Qt.AlignmentFlag.AlignCenter)

        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Correo electrónico")
        self.email_input.setMinimumWidth(400)
        layout.addWidget(self.email_input, alignment=Qt.AlignmentFlag.AlignCenter)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Contraseña")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setMinimumWidth(400)
        layout.addWidget(self.password_input, alignment=Qt.AlignmentFlag.AlignCenter)

        self.show_password_checkbox = QCheckBox("Mostrar contraseña")
        self.show_password_checkbox.setStyleSheet("color: white;")
        self.show_password_checkbox.stateChanged.connect(self.toggle_password_visibility)
        layout.addWidget(self.show_password_checkbox, alignment=Qt.AlignmentFlag.AlignCenter)

        self.login_message = QLabel("")
        layout.addWidget(self.login_message, alignment=Qt.AlignmentFlag.AlignCenter)

        login_button = QPushButton("Iniciar sesión")
        login_button.clicked.connect(self.login)
        layout.addWidget(login_button, alignment=Qt.AlignmentFlag.AlignCenter)

        self.login_screen.setLayout(layout)
        self.stacked_widget.addWidget(self.login_screen)

    def create_menu_screen(self):
        self.menu_screen = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        menu_label = QLabel("Menú Principal")
        menu_label.setFont(QFont("Roboto", 20, QFont.Weight.Bold))
        layout.addWidget(menu_label, alignment=Qt.AlignmentFlag.AlignCenter)

        send_email_button = QPushButton("Enviar correo")
        send_email_button.clicked.connect(self.clean_and_go_to_send_email)
        layout.addWidget(send_email_button, alignment=Qt.AlignmentFlag.AlignCenter)

        inbox_button = QPushButton("Bandeja de entrada")
        inbox_button.clicked.connect(self.clean_and_go_to_inbox)
        layout.addWidget(inbox_button, alignment=Qt.AlignmentFlag.AlignCenter)

        config_button = QPushButton("Configuración del servidor")
        config_button.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.server_config_screen))
        layout.addWidget(config_button, alignment=Qt.AlignmentFlag.AlignCenter)

        logout_button = QPushButton("Cerrar sesión")
        logout_button.clicked.connect(self.clean_and_go_to_login)
        layout.addWidget(logout_button, alignment=Qt.AlignmentFlag.AlignCenter)

        self.menu_screen.setLayout(layout)
        self.stacked_widget.addWidget(self.menu_screen)

    def create_send_email_screen(self):
        self.send_email_screen = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        send_label = QLabel("Enviar correo")
        send_label.setFont(QFont("Arial", 20, QFont.Weight.Bold))
        layout.addWidget(send_label, alignment=Qt.AlignmentFlag.AlignCenter)

        self.recipient_input = QLineEdit()
        self.recipient_input.setPlaceholderText("Destinatario(s) (separados por coma)")
        layout.addWidget(self.recipient_input)

        self.subject_input = QLineEdit()
        self.subject_input.setPlaceholderText("Asunto")
        layout.addWidget(self.subject_input)

        # Nuevo checkbox para usar el comando HEADER
        self.header_checkbox = QCheckBox("Usar comando HEADER")
        self.header_checkbox.setToolTip("Si se activa, se enviará la cabecera mediante el comando HEADER.")
        layout.addWidget(self.header_checkbox)

        # Campo para cabeceras adicionales (opcional)
        self.extra_headers_input = QLineEdit()
        self.extra_headers_input.setPlaceholderText("Cabeceras adicionales (opcional)")
        layout.addWidget(self.extra_headers_input)

        self.body_input = QTextEdit()
        self.body_input.setPlaceholderText("Cuerpo del mensaje")
        self.body_input.setMinimumHeight(300)
        layout.addWidget(self.body_input)

        self.send_message = QLabel("")
        layout.addWidget(self.send_message)

        button_layout = QHBoxLayout()
        send_button = QPushButton("Enviar")
        send_button.clicked.connect(self.send_email_action)
        button_layout.addWidget(send_button)

        back_button = QPushButton("Volver")
        back_button.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.menu_screen))
        button_layout.addWidget(back_button)

        button_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addLayout(button_layout)

        self.send_email_screen.setLayout(layout)
        self.stacked_widget.addWidget(self.send_email_screen)

    def create_inbox_screen(self):
        self.inbox_screen = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        inbox_label = QLabel("Bandeja de entrada")
        inbox_label.setFont(QFont("Arial", 20, QFont.Weight.Bold))
        layout.addWidget(inbox_label, alignment=Qt.AlignmentFlag.AlignCenter)

        self.inbox_table = QTableWidget()
        self.inbox_table.setColumnCount(4)
        self.inbox_table.setHorizontalHeaderLabels(["De", "Asunto", "Fecha", "Mensaje"])
        self.inbox_table.setSizeAdjustPolicy(QAbstractScrollArea.SizeAdjustPolicy.AdjustToContents)
        self.inbox_table.setColumnWidth(0, 200)
        self.inbox_table.setColumnWidth(1, 250)
        self.inbox_table.setColumnWidth(2, 150)
        self.inbox_table.setColumnWidth(3, 630)
        self.inbox_table.setRowCount(0)
        layout.addWidget(self.inbox_table)

        button_layout = QHBoxLayout()
        retrieve_button = QPushButton("Recuperar mensajes")
        retrieve_button.clicked.connect(self.retrieve_messages_action)
        button_layout.addWidget(retrieve_button)

        back_button = QPushButton("Volver")
        back_button.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.menu_screen))
        button_layout.addWidget(back_button)

        button_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addLayout(button_layout)

        self.inbox_screen.setLayout(layout)
        self.stacked_widget.addWidget(self.inbox_screen)

    def create_server_config_screen(self):
        self.server_config_screen = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        config_label = QLabel("Configuración del Servidor SMTP")
        config_label.setFont(QFont("Roboto", 20, QFont.Weight.Bold))
        layout.addWidget(config_label, alignment=Qt.AlignmentFlag.AlignCenter)

        self.server_input = QLineEdit()
        self.server_input.setPlaceholderText("Servidor SMTP")
        self.server_input.setText(self.smtp_server)
        layout.addWidget(self.server_input, alignment=Qt.AlignmentFlag.AlignCenter)

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Puerto SMTP")
        self.port_input.setText(str(self.smtp_port))
        layout.addWidget(self.port_input, alignment=Qt.AlignmentFlag.AlignCenter)

        button_layout = QHBoxLayout()
        save_button = QPushButton("Guardar")
        save_button.clicked.connect(self.save_server_config)
        button_layout.addWidget(save_button)

        back_button = QPushButton("Volver")
        back_button.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.menu_screen))
        button_layout.addWidget(back_button)

        layout.addLayout(button_layout)
        self.server_config_screen.setLayout(layout)
        self.stacked_widget.addWidget(self.server_config_screen)

    def save_server_config(self):
        server = self.server_input.text().strip()
        port_text = self.port_input.text().strip()
        if server:
            self.smtp_server = server
        try:
            port = int(port_text)
            self.smtp_port = port
        except ValueError:
            pass  # Aquí se podría mostrar un mensaje de error si el puerto no es un entero válido.
        self.stacked_widget.setCurrentWidget(self.menu_screen)

    def clean_and_go_to_login(self):
        self.email_input.clear()
        self.password_input.clear()
        self.login_message.setText("")
        self.stacked_widget.setCurrentWidget(self.login_screen)

    def clean_and_go_to_send_email(self):
        self.recipient_input.clear()
        self.subject_input.clear()
        self.body_input.clear()
        self.send_message.setText("")
        # Opcional: también limpiar los campos de cabecera si se deseara
        self.header_checkbox.setChecked(False)
        self.extra_headers_input.clear()
        self.stacked_widget.setCurrentWidget(self.send_email_screen)

    def clean_and_go_to_inbox(self):
        self.inbox_table.setRowCount(0)
        self.stacked_widget.setCurrentWidget(self.inbox_screen)

    def login(self):
        email = self.email_input.text().strip()
        password = self.password_input.text().strip()
        self.login_message.setText("")
        if not email or not password:
            self.login_message.setText("Por favor, completa todos los campos.")
            return

        def auth_task():
            try:
                self.login_message.setText("")
                result = asyncio.run(authentication(email, password,
                                                    smtp_server=self.smtp_server,
                                                    smtp_port=self.smtp_port))
                if result:
                    self.login_message.setText("Inicio de sesión exitoso.")
                    self.stacked_widget.setCurrentWidget(self.menu_screen)
                else:
                    self.login_message.setText("Usuario o contraseña incorrectos. Por favor, inténtalo de nuevo.")
            except Exception as e:
                self.login_message.setText(f"Error: {e}")

        thread = threading.Thread(target=auth_task)
        thread.start()

    def send_email_action(self):
        sender = self.email_input.text().strip()
        password = self.password_input.text().strip()
        recipients = self.recipient_input.text().strip()
        subject = self.subject_input.text().strip()
        body = self.body_input.toPlainText().strip()
        self.send_message.setText("")
        if not recipients or not subject or not body:
            self.send_message.setText("Por favor, completa todos los campos antes de enviar el correo.")
            return

        # Leer el estado del checkbox y el contenido de las cabeceras adicionales
        use_header_command = self.header_checkbox.isChecked()
        extra_headers = self.extra_headers_input.text().strip()

        def send_task():
            try:
                self.send_message.setText("")
                result = asyncio.run(send_email(sender, password, recipients, subject, body,
                                                use_header_command=use_header_command,
                                                extra_headers=extra_headers,
                                                smtp_server=self.smtp_server,
                                                smtp_port=self.smtp_port))
                if result:
                    self.send_message.setText("Correo enviado exitosamente.")
                else:
                    self.send_message.setText("Error al enviar el correo. Verifica los destinatarios.")
            except Exception as e:
                self.send_message.setText(f"Error: {e}")

        thread = threading.Thread(target=send_task)
        thread.start()

    def retrieve_messages_action(self):
        sender = self.email_input.text().strip()
        password = self.password_input.text().strip()

        def retrieve_task():
            try:
                messages = asyncio.run(retrieve_messages(sender, password,
                                                         smtp_server=self.smtp_server,
                                                         smtp_port=self.smtp_port))
                print(f"Mensajes procesados en lista: {messages}")
                text = ''.join(messages)
                print(f"Unión de los SMS: {text}")
                pattern = r'(De:.*?)(?=De:|$)'
                emails = re.findall(pattern, text, re.DOTALL)
                self.inbox_table.setRowCount(0)
                for index, email in enumerate(emails):
                    email = email.strip()
                    lines = email.split('\n')
                    from_address = ""
                    subject = ""
                    date = ""
                    body = ""
                    found_body = False
                    for line in lines:
                        if line.startswith("De:"):
                            from_address = line.replace("De:", "").strip()
                        elif line.startswith("Asunto:"):
                            subject = line.replace("Asunto:", "").strip()
                        elif line.startswith("Fecha:"):
                            date = line.replace("Fecha:", "").strip()
                        elif line.startswith("Para:"):
                            continue
                        elif line.strip() == "":
                            found_body = True
                        elif found_body:
                            body += line + "\n"
                    body = body.strip()
                    self.inbox_table.insertRow(index)
                    self.inbox_table.setItem(index, 0, QTableWidgetItem(from_address))
                    self.inbox_table.setItem(index, 1, QTableWidgetItem(subject))
                    self.inbox_table.setItem(index, 2, QTableWidgetItem(date))
                    body_item = QTableWidgetItem(body)
                    body_item.setTextAlignment(QtCore.Qt.AlignmentFlag.AlignTop | QtCore.Qt.AlignmentFlag.AlignLeft)
                    self.inbox_table.setItem(index, 3, body_item)
                    num_lines = len(body.splitlines())
                    row_height = max(30, num_lines * 35)
                    time.sleep(0.5)
                    self.inbox_table.setRowHeight(index, row_height)
                    for col in range(self.inbox_table.columnCount()):
                        self.inbox_table.item(index, col).setFlags(
                            self.inbox_table.item(index, col).flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable
                        )
                    print("Número de filas en la tabla:", self.inbox_table.rowCount())
                    for row in range(self.inbox_table.rowCount()):
                        print(f"Altura de la fila {row}: {self.inbox_table.rowHeight(row)}")
            except Exception as e:
                self.inbox_table.setRowCount(0)
                self.inbox_table.insertRow(0)
                self.inbox_table.setItem(0, 0, QTableWidgetItem("Error"))
                self.inbox_table.setItem(0, 1, QTableWidgetItem("-"))
                self.inbox_table.setItem(0, 2, QTableWidgetItem("-"))
                self.inbox_table.setItem(0, 3, QTableWidgetItem(str(e)))
        thread = threading.Thread(target=retrieve_task)
        thread.start()

    def toggle_password_visibility(self, state):
        if self.show_password_checkbox.isChecked():
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SMTPClientUI()
    window.show()
    sys.exit(app.exec())