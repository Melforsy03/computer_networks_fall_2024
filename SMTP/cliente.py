import asyncio
import base64
from email.utils import formatdate
import logging
import re
import argparse
import json

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Valores por defecto para el servidor y puerto SMTP
DEFAULT_SMTP_SERVER = "127.0.0.1"
DEFAULT_SMTP_PORT = 2525

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

async def send_email(sender, password, recipients, subject, message, extra_headers,
                     smtp_server=DEFAULT_SMTP_SERVER, smtp_port=DEFAULT_SMTP_PORT):
    logging.info("Iniciando envío de correo.")
    validate_email(sender)
    
    # Si recipients es una cadena, se separa usando la coma como separador.
    if isinstance(recipients, str):
        recipients = [r.strip() for r in recipients.split(",") if r.strip()]
    for r in recipients:
        validate_email(r)
    
    # Construir los encabezados
    headers = f"From: {sender}\r\n"
    headers += f"To: {', '.join(recipients)}\r\n"
    headers += f"Subject: {subject}\r\n"
    headers += f"Date: {formatdate(localtime=True)}\r\n"
    for key, value in extra_headers.items():
        headers += f"{key}: {value}\r\n"
    headers += "\r\n"
    
    # Mensaje completo: encabezados + cuerpo
    plain_message = headers + message

    reader, writer = None, None
    sent = False
    try:
        # Conexión en modo plano (sin SSL)
        reader, writer = await asyncio.open_connection(smtp_server, smtp_port)
        await read_response(reader)
        
        writer.write(b"EHLO localhost\r\n")
        await writer.drain()
        await read_response(reader)
        
        # Intentar autenticación con AUTH PLAIN; si el servidor responde "502", se ignora.
        try:
            auth_str = "\0" + sender + "\0" + password
            auth_b64 = base64.b64encode(auth_str.encode())
            writer.write(b"AUTH PLAIN " + auth_b64 + b"\r\n")
            await writer.drain()
            await read_response(reader)
        except Exception as e:
            if "502" in str(e):
                logging.warning("El servidor no implementa AUTH; se continúa sin autenticación.")
            else:
                raise e

        writer.write(f"MAIL FROM:<{sender}>\r\n".encode())
        await writer.drain()
        await read_response(reader)
        
        for r in recipients:
            writer.write(f"RCPT TO:<{r}>\r\n".encode())
            await writer.drain()
            await read_response(reader)
        
        writer.write(b"DATA\r\n")
        await writer.drain()
        await read_response(reader)
        
        writer.write(plain_message.encode() + b"\r\n.\r\n")
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

# --- Funciones authentication y retrieve_messages se mantienen (no son llamadas en main) ---

if __name__ == "__main__":
    # Deshabilitamos la ayuda automática para poder usar -h para header.
    parser = argparse.ArgumentParser(
        description="Cliente SMTP simple (texto plano).",
        add_help=False
    )
    parser.add_argument("-p", "--port", type=int, required=True, help="Puerto SMTP.")
    parser.add_argument("-u", "--host", type=str, required=True, help="Host SMTP.")
    parser.add_argument("-f", "--from_mail", type=str, required=True, help="Correo del remitente.")
    # El parámetro to_mail se define con nargs="+" (se unirá luego) porque se espera un JSON.
    parser.add_argument("-t", "--to_mail", type=str, required=True,
                        help="Lista de correos destinatarios en formato JSON.", nargs="+")
    # Para subject y body se usan nargs="*" para permitir que sean vacíos.
    parser.add_argument("-s", "--subject", type=str, help="Asunto del correo.", nargs="*")
    parser.add_argument("-b", "--body", type=str, help="Cuerpo del correo.", nargs="*")
    # Para header también se usa nargs="*"
    parser.add_argument("-h", "--header", type=str, default="{}", help="Encabezados adicionales en formato JSON.", nargs="*")
    parser.add_argument("-P", "--password", type=str, default="default", help="Contraseña del remitente")
    parser.add_argument("--help", action="help", default=argparse.SUPPRESS,
                        help="Muestra este mensaje de ayuda y sale.")

    args = parser.parse_args()

    # Unir los tokens de cada argumento en una cadena.
    # Si subject o body no se proporcionan, se usa cadena vacía.
    subject = " ".join(args.subject) if args.subject else ""
    body = " ".join(args.body) if args.body else ""
    header_str = " ".join(args.header) if args.header else "{}"
    to_mail_str = " ".join(args.to_mail)

    # Parsear el parámetro to_mail (se espera un JSON que sea una lista)
    try:
        recipients = json.loads(to_mail_str)
        if not isinstance(recipients, list):
            raise ValueError("to_mail debe ser una lista")
    except Exception as e:
        print(json.dumps({"status_code": 400, "message": f"Error al parsear to_mail: {e}"}))
        exit(1)

    # Parsear el parámetro header (se espera un JSON que sea un diccionario)
    try:
        extra_headers = json.loads(header_str)
        if not isinstance(extra_headers, dict):
            raise ValueError("header debe ser un diccionario")
    except Exception as e:
        print(json.dumps({"status_code": 400, "message": f"Error al parsear header: {e}"}))
        exit(1)

    SMTP_SERVER = args.host
    SMTP_PORT = args.port

    try:
        result = asyncio.run(send_email(args.from_mail, args.password,
                                          recipients, subject, body,
                                          extra_headers, SMTP_SERVER, SMTP_PORT))
        if result:
            output = {"status_code": 333, "message": "Correo enviado correctamente."}
        else:
            output = {"status_code": 500, "message": "Error al enviar el correo."}
    except Exception as e:
        output = {"status_code": 500, "message": f"Excepción: {e}"}

    print(json.dumps(output))
