from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QStackedWidget, QVBoxLayout, QWidget, QPushButton, QAbstractScrollArea,
    QLineEdit, QTextEdit, QLabel, QTableWidget, QTableWidgetItem, QHBoxLayout, QCheckBox
)
from PyQt6 import QtCore
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QTableWidgetItem

import sys
import re, time
import asyncio
import threading
from cliente import authentication, send_email, retrieve_messages

class SMTPClientUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cliente SMTP")
        self.setGeometry(100, 100, 1000, 800)  # Se ajusta el tamaño de la ventana

        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)

        # Estilo general
        self.setStyleSheet("""
            QMainWindow {
                background-color: #000000; /* Fondo negro */
            }
            QWidget {
                background-color: #000000; /* Fondo negro */
                color: white;
            }
            QPushButton {
                background-color: #4b0082; /* Botones morado oscuro */
                color: white;
                border: 1px solid #4b0082;
                border-radius: 3px;
                padding: 5px; /* Botones estilizados */
                font-size: 14px;
                min-width: 200px; /* Ancho mínimo */
                max-width: 200px; /* Ancho fijo */
            }
            QPushButton:hover {
                background-color: #660099; /* Cambio de color al pasar el mouse */
            }
            QLabel {
                color: white;
                font-size: 16px; /* Tamaño de texto */
            }
            QLineEdit, QTextEdit {
                background-color: #000000; /* Fondo negro */
                color: white;
                border: 1px solid #660099; /* Borde morado oscuro */
                border-radius: 3px;
                padding: 10px; /* Márgenes */
                font-size: 16px; /* Aumento de tamaño de fuente */
            }
            QTableWidget {
                background-color: #000000; /* Fondo negro */
                color: white;
                border: 1px solid #660099; /* Borde morado oscuro */
            }
            QTableWidget::item {
                border: 1px solid #660099; /* Borde morado oscuro */
            }
        """)
       
        self.create_login_screen()
        self.create_menu_screen()
        self.create_send_email_screen()
        self.create_inbox_screen()
        self.failed_attempts = 0
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

        # Opción para ver la contraseña
        self.show_password_checkbox = QCheckBox("Mostrar contraseña")
        self.show_password_checkbox.setStyleSheet("color: white;")
        self.show_password_checkbox.stateChanged.connect(self.toggle_password_visibility)
        layout.addWidget(self.show_password_checkbox, alignment=Qt.AlignmentFlag.AlignCenter)

        self.login_message = QLabel("")
        layout.addWidget(self.login_message, alignment=Qt.AlignmentFlag.AlignCenter)

        # ✅ Ahora `self.login_button` se usa en lugar de una variable local
        self.login_button = QPushButton("Iniciar sesión")
        self.login_button.clicked.connect(self.login)
        layout.addWidget(self.login_button, alignment=Qt.AlignmentFlag.AlignCenter)

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

        logout_button = QPushButton("Cerrar sesión")
        logout_button.clicked.connect(self.clean_and_go_to_login)
        layout.addWidget(logout_button, alignment=Qt.AlignmentFlag.AlignCenter)

        self.menu_screen.setLayout(layout)
        self.stacked_widget.addWidget(self.menu_screen)

    def create_send_email_screen(self):
        self.send_email_screen = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)  # Alineación hacia arriba

        send_label = QLabel("Enviar correo")
        send_label.setFont(QFont("Arial", 20, QFont.Weight.Bold))
        layout.addWidget(send_label, alignment=Qt.AlignmentFlag.AlignCenter)

        self.recipient_input = QLineEdit()
        self.recipient_input.setPlaceholderText("Destinatario")
        layout.addWidget(self.recipient_input)

        self.subject_input = QLineEdit()
        self.subject_input.setPlaceholderText("Asunto")
        layout.addWidget(self.subject_input)

        self.body_input = QTextEdit()
        self.body_input.setPlaceholderText("Cuerpo del mensaje")
        self.body_input.setMinimumHeight(300)  
        layout.addWidget(self.body_input)

        self.send_message = QLabel("")
        layout.addWidget(self.send_message)

        # Botones centrados
        button_layout = QHBoxLayout()
        send_button = QPushButton("Enviar")
        send_button.clicked.connect(self.send_email)
        button_layout.addWidget(send_button)

        back_button = QPushButton("Volver")
        back_button.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.menu_screen))
        button_layout.addWidget(back_button)

        button_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)  # Centramos los botones
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

        # columna
        self.inbox_table = QTableWidget()
        self.inbox_table.setColumnCount(4) 
        self.inbox_table.setHorizontalHeaderLabels(["De", "Asunto", "Fecha", "Mensaje"])

        self.inbox_table.setSizeAdjustPolicy(QAbstractScrollArea.SizeAdjustPolicy.AdjustToContents)

        # Cambiar el tamaño de las columnas
        self.inbox_table.setColumnWidth(0, 200)  
        self.inbox_table.setColumnWidth(1, 250)  
        self.inbox_table.setColumnWidth(2, 150) 
        self.inbox_table.setColumnWidth(3, 800)  
        
        self.inbox_table.setRowCount(0)
        layout.addWidget(self.inbox_table)
       
        # Botones centrados
        button_layout = QHBoxLayout()
        retrieve_button = QPushButton("Recuperar mensajes")
        retrieve_button.clicked.connect(self.retrieve_messages)
        button_layout.addWidget(retrieve_button)

        back_button = QPushButton("Volver")
        back_button.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.menu_screen))
        button_layout.addWidget(back_button)

        button_layout.setAlignment(Qt.AlignmentFlag.AlignCenter) 
        layout.addLayout(button_layout)

        self.inbox_screen.setLayout(layout)
        self.stacked_widget.addWidget(self.inbox_screen)

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
        self.stacked_widget.setCurrentWidget(self.send_email_screen)

    def clean_and_go_to_inbox(self):
        self.inbox_table.setRowCount(0)  # Limpia la tabla
        self.stacked_widget.setCurrentWidget(self.inbox_screen)
    def login(self):
        email = self.email_input.text()
        password = self.password_input.text()
        self.login_message.setText("")
        
        if not email or not password:
            self.login_message.setText("Por favor, completa todos los campos.")
            return
        
        def auth_task():
            try:
                result = asyncio.run(authentication(email, password))
            
                if result == "blocked":  # Caso en que la cuenta está bloqueada
                    self.login_message.setText("Cuenta bloqueada temporalmente. Inténtalo de nuevo más tarde.")
                    self.block_login()
                elif result:
                    self.failed_attempts = 0  # Restablecer intentos fallidos si se autentica
                    self.login_message.setText("Inicio de sesión exitoso.")
                    self.stacked_widget.setCurrentWidget(self.menu_screen)
                else:
                    self.failed_attempts += 1
                    if self.failed_attempts >= 3:
                        self.block_login()
                    else:
                        self.login_message.setText(f"Usuario o contraseña incorrectos. Intento {self.failed_attempts}/3.")
            except Exception as e:
                    self.login_message.setText(f"Error: {e}")

        thread = threading.Thread(target=auth_task)
        thread.start()
        
    def block_login(self):
            """🔹 Deshabilita el login tras 3 intentos fallidos por 30 segundos"""
            self.login_message.setText("Demasiados intentos fallidos. Espera 30 segundos.")
            self.email_input.setEnabled(False)
            self.password_input.setEnabled(False)
            self.login_button.setEnabled(False)

            def unblock():
                time.sleep(30)
                self.failed_attempts = 0
                self.email_input.setEnabled(True)
                self.password_input.setEnabled(True)
                self.login_button.setEnabled(True)
                self.login_message.setText("Puedes intentar nuevamente.")

            thread = threading.Thread(target=unblock)
            thread.start()
            
    def send_email(self):
        sender = self.email_input.text()
        password = self.password_input.text()
        recipient = self.recipient_input.text()
        subject = self.subject_input.text()
        body = self.body_input.toPlainText()
        self.login_message.setText("")
        
        # Validación de campos vacíos
        if not recipient or not subject or not body:
            self.send_message.setText("Por favor, completa todos los campos antes de enviar el correo.")
            return
    
        def send_task():
            try:
                self.login_message.setText("")
                result = asyncio.run(send_email(sender, password, recipient, subject, body))
                
                if result:
                    self.send_message.setText("Correo enviado exitosamente.")
                else:
                    self.send_message.setText("El destinatario no existe. Por favor, inténtalo de nuevo.")
            except Exception as e:
                self.send_message.setText(f"Error: {e}")

        thread = threading.Thread(target=send_task)
        thread.start()

    def retrieve_messages(self):
        sender = self.email_input.text()
        password = self.password_input.text()

        def retrieve_task():
            try:
                messages = asyncio.run(retrieve_messages(sender, password))
                print(f"Mensajes procesados en lista: {messages}")
                text = ''.join(messages)
                print(f"Unión de los SMS: {text}")

                # Usar una expresión regular para encontrar los bloques de correos
                pattern = r'(De:.*?)(?=De:|$)'
                emails = re.findall(pattern, text, re.DOTALL)

                # Limpiar la tabla antes de agregar nuevos mensajes
                self.inbox_table.setRowCount(0)

                # Procesar cada correo encontrado
                for index, email in enumerate(emails):
                    email = email.strip()  # Eliminar espacios en blanco al principio y al final
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
                        elif line.startswith("Para:"):  # Ignorar la línea que empieza con "Para:"
                            continue
                        elif line.strip() == "":
                            found_body = True
                        elif found_body:
                            body += line + "\n"

                    # Limpiar el cuerpo de posibles espacios en blanco al final
                    body = body.strip()
                    
                    # Insertar en la tabla
                    self.inbox_table.insertRow(index)
                    self.inbox_table.setItem(index, 0, QTableWidgetItem(from_address))
                    self.inbox_table.setItem(index, 1, QTableWidgetItem(subject))
                    self.inbox_table.setItem(index, 2, QTableWidgetItem(date))
                    
                    body_item = QTableWidgetItem(body)
                    body_item.setTextAlignment(QtCore.Qt.AlignmentFlag.AlignTop | QtCore.Qt.AlignmentFlag.AlignLeft)
                    self.inbox_table.setItem(index, 3, body_item)
                    
                    # **Cálculo del tamaño de la fila basado en las líneas del mensaje**
                    num_lines = len(body.splitlines()) 
                    row_height = max(30, num_lines * 35) 
                    time.sleep(0.05)
                    self.inbox_table.setRowHeight(index, row_height) 
                    
                    # Deshabilitar la edición de las celdas (solo lectura)
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
            print("Mostrar contraseña")
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            print("Ocultar contraseña")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SMTPClientUI()
    window.show()
    sys.exit(app.exec())
