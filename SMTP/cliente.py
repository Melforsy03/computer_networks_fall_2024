import asyncio
import base64
from cryptography.fernet import Fernet
import ssl
from email.utils import formatdate
import logging
import re

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Valores por defecto para el servidor y puerto SMTP
DEFAULT_SMTP_SERVER = "127.0.0.1"
DEFAULT_SMTP_PORT = 2525

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

async def authentication(sender, password, smtp_server=DEFAULT_SMTP_SERVER, smtp_port=DEFAULT_SMTP_PORT):
    logging.info("Iniciando autenticación.")
    validate_email(sender)

    ssl_context = ssl.create_default_context()
    ssl_context.load_verify_locations("server.crt")
    
    reader, writer = None, None
    is_authenticated = False

    try:
        reader, writer = await asyncio.open_connection(smtp_server, smtp_port, ssl=ssl_context)
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

        writer.write(b"QUIT\r\n")
        await writer.drain()
        await read_response(reader)

        logging.info("Se autenticó correctamente.")
        is_authenticated = True

    except Exception as e:
        logging.error(f"Error al autenticar: {e}")
    
    finally:
        if writer:
            writer.close()
            await writer.wait_closed()
        return is_authenticated

async def send_email(sender, password, recipients, subject, message,
                    smtp_server=DEFAULT_SMTP_SERVER, smtp_port=DEFAULT_SMTP_PORT):
    
    logging.info("Iniciando envío de correo.")
    validate_email(sender)
    
    if isinstance(recipients, str):
        recipients = [r.strip() for r in recipients.split(",") if r.strip()]
    for r in recipients:
        validate_email(r)

    headers = f"De: {sender}\nPara: {', '.join(recipients)}\nAsunto: {subject}\nFecha: {formatdate(localtime=True)}\n"
    #if extra_headers:
    #    headers += extra_headers + "\n"

    # Si se usa el comando HEADER, se cifra solo el cuerpo; de lo contrario, se cifra todo (cabecera + cuerpo)
    #if use_header_command:
    #    encrypted_body = cipher_suite.encrypt(message.encode())
    #else:
    full_message = headers + "\n" + message
    encrypted_body = cipher_suite.encrypt(full_message.encode())

    ssl_context = ssl.create_default_context()
    ssl_context.load_verify_locations("server.crt")
    
    reader, writer = None, None
    sent = False

    try:
        reader, writer = await asyncio.open_connection(smtp_server, smtp_port, ssl=ssl_context)
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

        for r in recipients:
            writer.write(f"RCPT TO:{r}\r\n".encode())
            await writer.drain()
            await read_response(reader)

        #if use_header_command:
        #    writer.write(f"HEADER {headers}\r\n".encode())
        #    await writer.drain()
        #    await read_response(reader)

        writer.write(b"DATA\r\n")
        await writer.drain()
        await read_response(reader)

        writer.write(encrypted_body + b"\r\n.\r\n")
        await writer.drain()
        await read_response(reader)

        writer.write(b"QUIT\r\n")
        await writer.drain()
        await read_response(reader)

        logging.info("Correo enviado correctamente.")
        sent = True

    except Exception as e:
        logging.error(f"Error al enviar el correo: {e}")
    
    finally:
        if writer:
            writer.close()
            await writer.wait_closed()
        return sent

async def retrieve_messages(sender, password, smtp_server=DEFAULT_SMTP_SERVER, smtp_port=DEFAULT_SMTP_PORT):
    logging.info("Conectando para recuperar mensajes.")
    ssl_context = ssl.create_default_context()
    ssl_context.load_verify_locations("server.crt")

    reader, writer = None, None
    messages = [] 

    try:
        reader, writer = await asyncio.open_connection(smtp_server, smtp_port, ssl=ssl_context)
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
                if raw_message.strip():
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
    recipients = ["user1@gmail.com", "user3@gmail.com"]  
    subject = "Asunto de prueba 2"
    message = "Este es un mensaje de prueba, para ver si coge sms."
    password = "tu_contraseña_secreta"

    # Parámetros para el uso del comando HEADER
    use_header_command = True
    extra_headers = "X-Custom-Header: Valor personalizado"

    asyncio.run(send_email(sender, password, recipients, subject, message))