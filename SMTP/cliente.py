import asyncio
import base64
from cryptography.fernet import Fernet
import ssl
from email.utils import formatdate
import logging
import re

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

SMTP_SERVER = "127.0.0.1"
SMTP_PORT = 2525

def load_key():
    logging.info("Cargando clave de cifrado.")
    with open("secret.key", "rb") as key_file:
        return key_file.read()

cipher_suite = Fernet(load_key())

def validate_email(email):
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.match(email_regex, email):
        raise ValueError(f"Dirección de correo inválida: {email}")

async def read_response(reader):
    response = await reader.read(1024)
    response_decoded = response.decode().strip()
    logging.debug(f"Respuesta del servidor: {response_decoded}")
    if not (response_decoded.startswith("2") or response_decoded.startswith("3")):
        raise Exception(f"Error del servidor: {response_decoded}")
    return response_decoded

async def authentication(sender, password):
    logging.info("Iniciando autenticacion.")
    validate_email(sender)

    ssl_context = ssl.create_default_context()
    ssl_context.load_verify_locations("server.crt")
    
    reader, writer = None, None
    Bool = False

    try:
        reader, writer = await asyncio.open_connection(SMTP_SERVER, SMTP_PORT, ssl=ssl_context)
        await read_response(reader)

        writer.write(b"EHLO localhost\r\n")
        await writer.drain()
        await read_response(reader)

        writer.write(b"AUTH LOGIN\r\n")
        await writer.drain()
        await read_response(reader)

        writer.write(base64.b64encode(sender.encode()) + b"\r\n")
        await writer.drain()
        await read_response(reader)

        writer.write(base64.b64encode(password.encode()) + b"\r\n")
        await writer.drain()
        response = await read_response(reader)

        # Verificar si el servidor respondió que la cuenta está bloqueada
        if "535 Account is temporarily locked" in response:
            logging.error("Cuenta bloqueada temporalmente.")
            return "blocked"  # Retornar un estado especial para indicar bloqueo

        writer.write(b"QUIT\r\n")
        await writer.drain()
        await read_response(reader)

        logging.info("Se autentico correctamente.")
        Bool = True

    except Exception as e:
        logging.error(f"Error al autenticar: {e}")
    
    finally:
        if writer:
            writer.close()
            await writer.wait_closed()
        return Bool


async def send_email(sender, password, recipient, subject, message):
    logging.info("Iniciando envío de correo.")
    validate_email(sender)
    validate_email(recipient)

    headers = f"De: {sender}\nPara: {recipient}\nAsunto: {subject}\nFecha: {formatdate(localtime=True)}\n"
    full_message = headers + "\n" + message

    encrypted_message = cipher_suite.encrypt(full_message.encode())

    ssl_context = ssl.create_default_context()
    ssl_context.load_verify_locations("server.crt")
    
    reader, writer = None, None
    Bool = False

    try:
        reader, writer = await asyncio.open_connection(SMTP_SERVER, SMTP_PORT, ssl=ssl_context)
        await read_response(reader)

        writer.write(b"EHLO localhost\r\n")
        await writer.drain()
        await read_response(reader)

        writer.write(b"AUTH LOGIN\r\n")
        await writer.drain()
        await read_response(reader)

        writer.write(base64.b64encode(sender.encode()) + b"\r\n")
        await writer.drain()
        await read_response(reader)

        writer.write(base64.b64encode(password.encode()) + b"\r\n")
        await writer.drain()
        await read_response(reader)

        writer.write(f"MAIL FROM:{sender}\r\n".encode())
        await writer.drain()
        await read_response(reader)

        writer.write(f"RCPT TO:{recipient}\r\n".encode())
        await writer.drain()
        await read_response(reader)

        writer.write(b"DATA\r\n")
        await writer.drain()
        await read_response(reader)

        writer.write(encrypted_message + b"\r\n.\r\n")
        await writer.drain()
        await read_response(reader)

        writer.write(b"QUIT\r\n")
        await writer.drain()
        await read_response(reader)

        logging.info("Correo enviado correctamente.")
        Bool = True

    except Exception as e:
        logging.error(f"Error al enviar el correo: {e}")
    
    finally:
        if writer:
            writer.close()
            await writer.wait_closed()
        return Bool

async def retrieve_messages(sender, password):
    logging.info("Conectando para recuperar mensajes.")
    ssl_context = ssl.create_default_context()
    ssl_context.load_verify_locations("server.crt")

    reader, writer = None, None
    messages = [] 

    try:
        reader, writer = await asyncio.open_connection(SMTP_SERVER, SMTP_PORT, ssl=ssl_context)
        await read_response(reader)

        writer.write(b"EHLO localhost\r\n")
        await writer.drain()
        await read_response(reader)

        writer.write(b"AUTH LOGIN\r\n")
        await writer.drain()
        await read_response(reader)

        writer.write(base64.b64encode(sender.encode()) + b"\r\n")
        await writer.drain()
        await read_response(reader)

        writer.write(base64.b64encode(password.encode()) + b"\r\n")
        await writer.drain()
        await read_response(reader)

        logging.debug("Iniciando comando RETRIEVE.")
        writer.write(b"RETRIEVE\r\n")
        await writer.drain()

        response = b""
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(1024), timeout=5)  
                if not chunk:  
                    break
                response += chunk

                if response.endswith(b"\r\n.\r\n"):
                    break

            except asyncio.TimeoutError:
                logging.warning("Timeout al esperar más datos del servidor.")
                break

        try:
            response_decoded = response.decode(errors='replace')
            logging.info(f"Mensajes recibidos:\n{response_decoded}")
            
            raw_messages = response_decoded.split("\r\n.\r\n")
            
            for raw_message in raw_messages:
                if raw_message.strip():  # Ignorar bloques vacíos
                    messages.append(raw_message.strip())
            
        except Exception as decode_error:
            logging.error(f"Error al decodificar los mensajes: {decode_error}")
            raise

        writer.write(b"QUIT\r\n")
        await writer.drain()
        await read_response(reader)

    except Exception as e:
        logging.error(f"Error al recuperar mensajes cliente: {e}")
    
    finally:
        if writer:
            try:
                logging.info("Cerrando la conexión.")
                writer.close()
                await writer.wait_closed()
            except Exception as close_error:
                logging.warning(f"Error al cerrar la conexión: {close_error}")

    return messages

if __name__ == "__main__":
    sender = "user2@gmail.com"  
    recipient = "user1@gmail.com"
    subject = "Asunto de prueba 2"
    message = "Este es un mensaje de prueba, para ver si coge sms."
