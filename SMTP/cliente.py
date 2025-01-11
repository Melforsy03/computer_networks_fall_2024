import asyncio
import base64
from cryptography.fernet import Fernet
import ssl
from email.utils import formatdate
import logging

# Configurar logs
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

SMTP_SERVER = "127.0.0.1"
SMTP_PORT = 2525

def load_key():
    logging.info("Cargando clave de cifrado.")
    with open("secret.key", "rb") as key_file:
        return key_file.read()

cipher_suite = Fernet(load_key())

def validate_email(email):
    logging.debug(f"Validando dirección de correo: {email}")
    pass  # Validación desactivada para pruebas

async def read_response(reader):
    # Leer la respuesta del servidor SMTP
    response = await reader.read(1024)
    response_decoded = response.decode()
    logging.debug(f"Respuesta del servidor: {response_decoded.strip()}")

    if not (response_decoded.startswith("2") or response_decoded.startswith("3") or response_decoded.startswith("5")):
        logging.error(f"Error del servidor: {response_decoded.strip()}")
        raise Exception(f"Error del servidor: {response_decoded}")
    
    return response_decoded

# Elimina las líneas donde defines USERNAME y PASSWORD de forma fija
# USERNAME = "user"
# PASSWORD = "password"

# Nueva función que recibirá los valores de USERNAME y PASSWORD como parámetros
async def send_email(sender, recipient, subject, message, username, password):
    logging.info("Iniciando envío de correo con credenciales externas.")
    validate_email(sender)
    validate_email(recipient)

    # Construir el mensaje
    logging.debug("Construyendo el mensaje.")
    headers = f"From: {sender}\nTo: {recipient}\nSubject: {subject}\nDate: {formatdate(localtime=True)}\n"
    full_message = headers + "\n" + message

    # Cifrar el mensaje
    logging.debug("Cifrando el mensaje.")
    encrypted_message = cipher_suite.encrypt(full_message.encode())

    ssl_context = ssl.create_default_context()
    ssl_context.load_verify_locations("server.crt")
    
    reader, writer = None, None

    try:
        # Abrir conexión
        logging.info(f"Conectando al servidor SMTP en {SMTP_SERVER}:{SMTP_PORT}.")
        reader, writer = await asyncio.open_connection(SMTP_SERVER, SMTP_PORT, ssl=ssl_context)

        # Leer bienvenida del servidor
        await read_response(reader)

        # EHLO
        logging.info("Enviando comando EHLO.")
        writer.write(b"EHLO\r\n")
        await writer.drain()
        await read_response(reader)

        # AUTH LOGIN
        logging.info("Iniciando autenticación.")
        writer.write(b"AUTH LOGIN\r\n")
        await writer.drain()
        await read_response(reader)

        # Enviar nombre de usuario (pasando el username desde la función externa)
        logging.debug("Enviando nombre de usuario.")
        writer.write(base64.b64encode(username.encode()) + b"\r\n")
        await writer.drain()
        await read_response(reader)

        # Enviar contraseña (pasando el password desde la función externa)
        logging.debug("Enviando contraseña.")
        writer.write(base64.b64encode(password.encode()) + b"\r\n")
        await writer.drain()
        await read_response(reader)

        # MAIL FROM
        logging.info(f"Enviando comando MAIL FROM para: {sender}.")
        writer.write(f"MAIL FROM:<{sender}>\r\n".encode())
        await writer.drain()
        await read_response(reader)

        # RCPT TO
        logging.info(f"Enviando comando RCPT TO para: {recipient}.")
        writer.write(f"RCPT TO:<{recipient}>\r\n".encode())
        await writer.drain()
        await read_response(reader)

        # DATA
        logging.info("Enviando comando DATA.")
        writer.write(b"DATA\r\n")
        await writer.drain()
        await read_response(reader)

        # Enviar mensaje cifrado
        logging.info("Enviando el mensaje cifrado.")
        writer.write(encrypted_message + b"\r\n.\r\n")
        await writer.drain()
        await read_response(reader)

        # QUIT
        logging.info("Enviando comando QUIT.")
        writer.write(b"QUIT\r\n")
        await writer.drain()
        await read_response(reader)

        logging.info("Correo enviado correctamente.")

    except Exception as e:
        logging.error(f"Error al enviar el correo: {e}")
    
    finally:
        if writer:
            logging.info("Cerrando la conexión con el servidor.")
            writer.close()
            await writer.wait_closed()

