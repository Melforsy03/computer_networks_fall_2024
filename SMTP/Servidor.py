import asyncio
import logging
import base64
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import ssl
from aiohttp import web

HOST = "127.0.0.1"
PORT = 2525
EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
MAX_EMAIL_SIZE = 52428800  # 50 MB

# Array de usuarios con contraseñas
USERS = {
    "user1@gmail.com": "password1",
    "user2@gmail.com": "password2",
    "user3@gmail.com": "password3",
}

# Configuración de fuerza bruta
MAX_FAILED_ATTEMPTS = 3 
BLOCK_TIME = timedelta(minutes=5)  
failed_attempts = {}  

def is_blocked(client_address, username):
    # Verificar si la IP o el usuario está bloqueado
    if username in failed_attempts:
        attempts, block_time = failed_attempts[username]
        if attempts >= MAX_FAILED_ATTEMPTS and datetime.now() < block_time:
            return True
        elif datetime.now() >= block_time:
            del failed_attempts[username]  # Desbloquear usuario
            
    if client_address in failed_attempts:
        attempts, block_time = failed_attempts[client_address]
        if attempts >= MAX_FAILED_ATTEMPTS and datetime.now() < block_time:
            return True
        elif datetime.now() >= block_time:
            del failed_attempts[client_address]  # Desbloquear IP
            
    return False

def register_failed_attempt(username, client_address):
    if username not in failed_attempts:
        failed_attempts[username] = [0, datetime.now()]
    failed_attempts[username][0] += 1
    if failed_attempts[username][0] >= MAX_FAILED_ATTEMPTS:
        failed_attempts[username][1] = datetime.now() + BLOCK_TIME  # Bloqueo de 30s
    
    if client_address not in failed_attempts:
        failed_attempts[client_address] = [0, datetime.now()]
    failed_attempts[client_address][0] += 1
    if failed_attempts[client_address][0] >= MAX_FAILED_ATTEMPTS:
        failed_attempts[client_address][1] = datetime.now() + BLOCK_TIME  # Bloqueo de 30s

# Configuración de logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

try:
    with open("secret.key", "rb") as key_file:
        key = key_file.read()
except FileNotFoundError:
    logging.error("Archivo de clave de cifrado no encontrado.")
    exit(1)

cipher_suite = Fernet(key)

async def handle_client(reader, writer):
    client_address = writer.get_extra_info("peername")
    logs = []

    logging.info(f"Conexión establecida desde {client_address}")
    logs.append(f"Conexión establecida desde {client_address}")

    if is_blocked(client_address , ""):
        writer.write(b"421 Too many failed attempts. Try again later.\r\n")
        await writer.drain()
        logging.warning(f"Conexión rechazada para {client_address}: demasiados intentos fallidos.")
        writer.close()
        await writer.wait_closed()
        return
    
    writer.write(b"220 localhost Simple SMTP Server Ready\r\n")
    await writer.drain()

    mail_from = None
    rcpt_to = None
    data_mode = False
    email_data = []
    authenticated_user = None
    email_header = None


    while True:
        try:
            # Leer comando del cliente
            data = await reader.readline()
            if not data:
                logging.warning(f"Cliente {client_address} cerró la conexión.")
                logs.append(f"Cliente {client_address} cerró la conexión.")
                break

            command = data.decode("utf-8").strip()
            logging.info(f"Cliente {client_address}: {command}")
            logs.append(f"Cliente {client_address}: {command}")

            if command.upper().startswith("EHLO") or command.upper().startswith("HELO"):
                writer.write(b"250 OK\r\n")
                logging.info("Servidor: 250 OK (EHLO)")
                await writer.drain()
                continue

            elif not authenticated_user:
                if command.upper().startswith("AUTH LOGIN"):
                    writer.write(b"334 VXNlcm5hbWU6\r\n")
                    await writer.drain()

                    username = base64.b64decode(await reader.readline()).decode("utf-8").strip()
                    writer.write(b"334 UGFzc3dvcmQ6\r\n")
                    await writer.drain()

                    password = base64.b64decode(await reader.readline()).decode("utf-8").strip()

                    if is_blocked(client_address, username):
                        writer.write(b"535 Account is temporarily locked. Try again later.\r\n")
                        await writer.drain()
                        logging.warning(f"Intento de autenticación bloqueado para {username}.")
                        break

                    if username in USERS and USERS[username] == password:
                        authenticated_user = username
                        writer.write(b"235 Authentication successful\r\n")
                        await writer.drain()
                        continue
                    else:
                        register_failed_attempt(username,client_address)
                        writer.write(b"535 Authentication failed\r\n")
                        await writer.drain()
                        logging.warning(f"Intento de autenticación fallido para {username}.")
                        break
                else:
                    writer.write(b"530 Authentication required\r\n")
                    await writer.drain()
                    continue
                
            if data_mode:
                if command == ".":
                    if len("\n".join(email_data)) > MAX_EMAIL_SIZE:
                        writer.write(b"552 Message size exceeds limit\r\n")
                        logging.info("Servidor: 552 Message size exceeds limit")
                        logs.append("Servidor: 552 Message size exceeds limit")
                    else:
                        # Descifrar el mensaje
                        try:
                            decrypted_message = cipher_suite.decrypt("\n".join(email_data).encode()).decode()
                            logging.info(f"Correo recibido de {client_address}:\n{decrypted_message}")
                            logs.append(f"Correo recibido de {client_address}:\n{decrypted_message}")
                            save_email(mail_from, rcpt_to, decrypted_message)
                            writer.write(b"250 OK\r\n")
                            logging.info("Servidor: 250 OK")
                            logs.append("Servidor: 250 OK")
                        except Exception as e:
                            logging.error(f"Error al descifrar el mensaje: {e}")
                            logs.append(f"Error al descifrar el mensaje: {e}")
                            writer.write(b"550 Failed to decrypt message\r\n")
                            logging.info("Servidor: 550 Failed to decrypt message")
                            logs.append("Servidor: 550 Failed to decrypt message")
                    email_data = []
                    data_mode = False
                else:
                    email_data.append(command)
            else:
                if command.upper().startswith("MAIL FROM:"):
                    mail_from = command[10:].strip()
                    if mail_from not in USERS:
                        writer.write(b"550 Sender not recognized\\r\\n")
                    else:
                        writer.write(b"250 OK\\r\\n")
                elif command.upper().startswith("RCPT TO:"):
                    
                    if rcpt_to is None:
                        rcpt_to = []
                    email_recipient = command[8:].strip()
                    if email_recipient in USERS:
                        rcpt_to.append(email_recipient)
                        writer.write(b"250 OK\r\n")
                    else:
                        writer.write(b"550 Recipient not recognized\r\n")

                elif command.upper() == "DATA":
                    writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    logging.info("Servidor: 354 End data with <CR><LF>.<CR><LF>")
                    logs.append("Servidor: 354 End data with <CR><LF>.<CR><LF>")
                    data_mode = True
                    
                elif command.upper() == "RETRIEVE":
                    if not authenticated_user:
                        writer.write(b"530 Authentication required\r\n")
                    else:
                        try:
                            inbox_file = f"{authenticated_user}_inbox.txt"
                            try:
                                with open(inbox_file, "r") as f:
                                    messages = f.readlines()
                                if not messages:
                                    writer.write(b"250 No messages found\r\n")
                                else:
                                    writer.write(b"250 Messages retrieved:\r\n")
                                    for message in messages:
                                        writer.write(message.encode() + b"\r\n")
                                    writer.write(b".\r\n")  # Finaliza la transmisión
                            except FileNotFoundError:
                                writer.write(b"250 No messages found\r\n")
                        except Exception as e:
                            logging.error(f"Error al recuperar mensajes servidor: {e}")
                            writer.write(b"550 Error retrieving messages\r\n")
                    await writer.drain()
                elif command.upper() == "QUIT":
                    writer.write(b"221 Bye\r\n")
                    logging.info("Servidor: 221 Bye")
                    logs.append("Servidor: 221 Bye")
                    await writer.drain()
                    break
                else:
                    writer.write(b"500 Syntax error, command unrecognized\r\n")
                    logging.info("Servidor: 500 Syntax error, command unrecognized")
                    logs.append("Servidor: 500 Syntax error, command unrecognized")
            await writer.drain()
        except Exception as e:
            logging.error(f"Error con el cliente {client_address}: {e}")
            logs.append(f"Error con el cliente {client_address}: {e}")
            break

    logging.info(f"Conexión cerrada con {client_address}")
    logs.append(f"Conexión cerrada con {client_address}")
    writer.close()
    await writer.wait_closed()

def save_email(mail_from, recipients, email_data):
    logging.info(f"Guardando correo de {mail_from} para {', '.join(recipients)}.")
    for rcpt_to in recipients:
        try:
            inbox_file = f"{rcpt_to}_inbox.txt"
            with open(inbox_file, "a") as f:
                f.write(f"\nDe: {mail_from}\nPara: {rcpt_to}\n{email_data}\n\n")
        except IOError as e:
            logging.error(f"Error al guardar el correo para {rcpt_to}: {e}")


async def start_server():
 # Crear contexto SSL
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile="server.crt", keyfile="server.key")  # Requiere certificados

    # Iniciar servidor con SSL
    server = await asyncio.start_server(handle_client, HOST, PORT, ssl=ssl_context)
    logging.info(f"Servidor SMTP escuchando en {HOST}:{PORT} con TLS...")

    async with server:
        await server.serve_forever()


async def start_smtp_server():
    from Servidor import start_server  # Asegúrate de importar correctamente tu función `start_server`
    await start_server()
if __name__ == "__main__":
    asyncio.run(start_smtp_server())