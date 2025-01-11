from kivy.lang import Builder
from kivymd.app import MDApp
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.textfield import MDTextField
from kivymd.uix.label import MDLabel
from kivymd.uix.boxlayout import BoxLayout
from kivymd.uix.spinner import MDSpinner
from kivymd.toast import toast
from kivymd.uix.datatables import MDDataTable
from kivy.uix.scrollview import ScrollView  # Importar ScrollView si no está importado
from kivymd.uix.dialog import MDDialog
from kivy.uix.scrollview import ScrollView
from kivymd.uix.card import MDCard
from kivy.metrics import dp
import asyncio
import re
from cliente import send_email
from Servidor import read_emails_from_file
import threading
from Servidor import start_server

EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
# Almacenamiento de usuarios (esto puede estar en un archivo o base de datos)
USER_DATA = {}

# Layout de la ventana principal
class MainWindow(BoxLayout):
    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.spacing = 10
        self.padding = 20
        self.app = app

        # Título
        self.add_widget(MDLabel(text="Bienvenido a SMTP",
                                halign="center",
                                font_style="H3",
                                size_hint=(1, 0.2)))

        # Botones para Cliente y Servidor
        self.add_widget(MDRaisedButton(text="Envío de correos",
                                        size_hint=(None, None),
                                        size=("200dp", "50dp"),
                                        pos_hint={"center_x": 0.5},
                                        on_press=self.app.show_client_interface))

        self.add_widget(MDRaisedButton(text="Correos recibidos",
                                        size_hint=(None, None),
                                        size=("200dp", "50dp"),
                                        pos_hint={"center_x": 0.5},
                                        on_press=self.app.show_server_interface))

class LoginWindow(BoxLayout):
    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.spacing = 10
        self.padding = 30
        self.app = app

        self.add_widget(MDLabel(text="Login", halign="center", font_style="H4", size_hint=(1, 0.1)))

        self.email_input = MDTextField(hint_text="Introduce tu correo", size_hint=(1, None), height="40dp")
        self.add_widget(self._build_labeled_field("Correo:", self.email_input))

        self.password_input = MDTextField(hint_text="Introduce tu contraseña", size_hint=(1, None), height="40dp", password=True)
        self.add_widget(self._build_labeled_field("Contraseña:", self.password_input))

        self.login_button = MDRaisedButton(text="Iniciar Sesión", size_hint=(None, None), size=("200dp", "50dp"), pos_hint={"center_x": 0.5}, on_press=self.login)
        self.add_widget(self.login_button)

        self.register_button = MDRaisedButton(text="Registrar", size_hint=(None, None), size=("200dp", "50dp"), pos_hint={"center_x": 0.5}, on_press=self.app.show_register_interface)
        self.add_widget(self.register_button)

    def _build_labeled_field(self, label_text, input_field):
        layout = BoxLayout(orientation="vertical", size_hint=(1, None), height="100dp")
        layout.add_widget(MDLabel(text=label_text, halign="left"))
        layout.add_widget(input_field)
        return layout

    def login(self, instance):
        email = self.email_input.text
        password = self.password_input.text

        if email not in USER_DATA or USER_DATA[email] != password:
            toast("Credenciales incorrectas.")
            return

        # Guardar las credenciales en la aplicación
        self.app.set_user_credentials(email, password)

        toast("Login exitoso.")
        self.app.show_main_interface()


class RegisterWindow(BoxLayout):
    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.spacing = 10
        self.padding = 30
        self.app = app

        self.add_widget(MDLabel(text="Registro", halign="center", font_style="H4", size_hint=(1, 0.1)))

        self.email_input = MDTextField(hint_text="Introduce tu correo", size_hint=(1, None), height="40dp")
        self.add_widget(self._build_labeled_field("Correo:", self.email_input))

        self.password_input = MDTextField(hint_text="Introduce tu contraseña", size_hint=(1, None), height="40dp", password=True)
        self.add_widget(self._build_labeled_field("Contraseña:", self.password_input))

        self.confirm_password_input = MDTextField(hint_text="Confirma tu contraseña", size_hint=(1, None), height="40dp", password=True)
        self.add_widget(self._build_labeled_field("Confirmar Contraseña:", self.confirm_password_input))

        self.register_button = MDRaisedButton(text="Registrar", size_hint=(None, None), size=("200dp", "50dp"), pos_hint={"center_x": 0.5}, on_press=self.register)
        self.add_widget(self.register_button)

        self.login_button = MDRaisedButton(text="Volver al Login", size_hint=(None, None), size=("200dp", "50dp"), pos_hint={"center_x": 0.5}, on_press=self.app.show_login_interface)
        self.add_widget(self.login_button)

    def _build_labeled_field(self, label_text, input_field):
        layout = BoxLayout(orientation="vertical", size_hint=(1, None), height="100dp")
        layout.add_widget(MDLabel(text=label_text, halign="left"))
        layout.add_widget(input_field)
        return layout

    def register(self, instance):
        email = self.email_input.text
        password = self.password_input.text
        confirm_password = self.confirm_password_input.text

        if email in USER_DATA:
            toast("El correo ya está registrado.")
            return

        if password != confirm_password:
            toast("Las contraseñas no coinciden.")
            return

        USER_DATA[email] = password
        toast("Registro exitoso.")
        self.app.show_login_interface()

class ClientWindow(BoxLayout):
    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.spacing = 10
        self.padding = 30
        self.app = app
        self.spinner = None  # Agregar una referencia al spinner

        # Título
        self.add_widget(MDLabel(text="Enviar Correo",
                                halign="center",
                                font_style="H4",
                                size_hint=(1, 0.1)))

        # Remitente
        self.sender_input = MDTextField(hint_text="Introduce el remitente", size_hint=(1, None), height="40dp")
        self.add_widget(self._build_labeled_field("Remitente:", self.sender_input))

        # Destinatario
        self.recipient_input = MDTextField(hint_text="Introduce el destinatario", size_hint=(1, None), height="40dp")
        self.add_widget(self._build_labeled_field("Destinatario:", self.recipient_input))

        # Asunto
        self.subject_input = MDTextField(hint_text="Introduce el asunto", size_hint=(1, None), height="40dp")
        self.add_widget(self._build_labeled_field("Asunto:", self.subject_input))

        # Mensaje
        self.message_input = MDTextField(hint_text="Introduce tu mensaje", multiline=True, size_hint=(1, None), height="200dp")
        message_scroll = ScrollView(size_hint=(1, None), height="60dp")  # Ajustar el tamaño del ScrollView
        message_scroll.add_widget(self.message_input)
        self.add_widget(self._build_labeled_field("Mensaje:", message_scroll))

        # Botón Enviar
        self.send_button = MDRaisedButton(text="Enviar",
                                          size_hint=(None, None),
                                          size=("200dp", "50dp"),
                                          pos_hint={"center_x": 0.5},
                                          on_press=self.send_message)
        self.add_widget(self.send_button)

        # Botón Volver
        self.add_widget(MDRaisedButton(text="Volver",
                                       size_hint=(None, None),
                                       size=("200dp", "50dp"),
                                       pos_hint={"center_x": 0.5},
                                       on_press=self.app.show_main_interface))

    def _build_labeled_field(self, label_text, input_field):
        layout = BoxLayout(orientation="vertical", size_hint=(1, None), height="100dp")
        layout.add_widget(MDLabel(text=label_text, halign="left"))
        layout.add_widget(input_field)
        return layout

    async def send_message_async(self, sender, recipient, subject, message):
        try:
            # Usar las credenciales del usuario almacenadas en la app
            username = self.app.username
            password = self.app.password

            # Enviar correo utilizando las credenciales del usuario
            await send_email(username, password, sender, recipient, subject, message)
            toast("Correo enviado correctamente.")  # Usamos el toast aquí
            self.app.show_main_interface()
        except Exception as e:
            toast(f"Error: {str(e)}")  # Usamos el toast aquí
        finally:
            # Eliminar el spinner después de que termine el proceso
            if self.spinner:
                self.remove_widget(self.spinner)
                self.spinner = None

    def send_message(self, instance):
        sender = self.sender_input.text
        recipient = self.recipient_input.text
        subject = self.subject_input.text
        message = self.message_input.text

        # Validaciones
        if not all([sender, recipient, subject, message]):
            toast("Todos los campos deben estar completos.")  # Usamos el toast aquí
            return

        if not re.match(EMAIL_REGEX, sender):
            toast("El remitente no tiene un formato válido.")  # Usamos el toast aquí
            return

        if not re.match(EMAIL_REGEX, recipient):
            toast("El destinatario no tiene un formato válido.")  # Usamos el toast aquí
            return

        # Spinner de carga (solo uno)
        if not self.spinner:
            self.spinner = MDSpinner(size_hint=(None, None), size=("48dp", "48dp"), pos_hint={"center_x": 0.5, "center_y": 0.5})
            self.add_widget(self.spinner)

        # Ejecutar la tarea asincrónica correctamente
        asyncio.run(self.send_message_async(sender, recipient, subject, message))


class ServerWindow(BoxLayout):
    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.spacing = 10
        self.padding = (30, 20, 30, 0)
        self.app = app

        # Título
        self.add_widget(MDLabel(text="Bandeja de Correos",
                                halign="center",
                                theme_text_color="Custom",
                                text_color=(1, 1, 1, 1),
                                font_style="H4",
                                size_hint=(1, 0.5)))

        # Scroll para mensajes
        self.messages_list = ScrollView(size_hint=(1, 1), height=300)
        self.messages_box = BoxLayout(orientation="vertical", size_hint_y=None, spacing=10)
        self.messages_box.bind(minimum_height=self.messages_box.setter('height'))

        # Leer los correos desde el archivo y mostrarlos
        emails = read_emails_from_file() 
        
        for email in emails:
            message = MDCard(
                size_hint=(0.6, None),
                padding=10,
                pos_hint={"x": 0.05},
                adaptive_height=True,
            )
            message.add_widget(MDLabel(
                text=email,
                halign="left",
                theme_text_color="Secondary",
                size_hint_y=None,
                valign="top",
                adaptive_height=True,
            ))
            self.messages_box.add_widget(message)

        self.messages_list.add_widget(self.messages_box)
        self.add_widget(self.messages_list)

        # Botón Volver
        self.back_button = MDRaisedButton(text="Volver",
                                          size_hint=(None, None),
                                          size=("200dp", "50dp"),
                                          pos_hint={"center_x": 0.5},
                                          on_press=self.app.show_main_interface)
        self.add_widget(self.back_button)

# Clase principal de la aplicación
class SMTPApp(MDApp):
    def build(self):
        # Configurar el tema con fondo oscuro y color morado
        self.theme_cls.primary_palette = "Purple"  
        self.theme_cls.primary_hue = "500" 
        self.theme_cls.theme_style = "Dark" 
        self.theme_cls.accent_palette = "Purple"  
        self.theme_cls.accent_hue = "500" 
        
        self.username = None
        self.password = None
        self.main_window = LoginWindow(self)
        return self.main_window
    
    def set_user_credentials(self, username, password):
        """Guardar las credenciales del usuario."""
        self.username = username
        self.password = password
        
    def show_login_interface(self, *args):
        self.root.clear_widgets()
        self.root.add_widget(LoginWindow(self))

    def show_register_interface(self, *args):
        self.root.clear_widgets()
        self.root.add_widget(RegisterWindow(self))

    def show_main_interface(self, *args):
        self.root.clear_widgets()
        self.root.add_widget(MainWindow(self))

    def show_client_interface(self, *args):
        self.root.clear_widgets()
        self.root.add_widget(ClientWindow(self))

    def show_server_interface(self, *args):
        self.root.clear_widgets()
        self.root.add_widget(ServerWindow(self))

    def start_server_thread(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(start_server())

    def on_start(self):
        # Iniciar el servidor en un hilo separado
        server_thread = threading.Thread(target=self.start_server_thread)
        server_thread.start()


if __name__ == "__main__":
    SMTPApp().run()
