import asyncio
import base64
import argparse  
import json    
from email.utils import formatdate
import logging
import re

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

SMTP_SERVER = "127.0.0.1"
SMTP_PORT = 2525

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

async def send_email(sender, password, recipients, subject, message, extra_headers):
    """
    Envía un correo electrónico utilizando el flujo SMTP básico.
    
    Parámetros:
      - sender: dirección de correo del remitente.
      - password: contraseña para la autenticación.
      - recipients: lista de direcciones de correo destinatarios.
      - subject: asunto del mensaje.
      - message: cuerpo del mensaje.
      - extra_headers: diccionario con encabezados adicionales (por ejemplo, {"CC": "cc@example.com"}).
    """
    logging.info("Iniciando envío de correo.")

    validate_email(sender)
    for rec in recipients:
        validate_email(rec)

    headers = f"From: {sender}\r\n"
    headers += f"To: {', '.join(recipients)}\r\n"
    headers += f"Subject: {subject}\r\n"
    headers += f"Date: {formatdate(localtime=True)}\r\n"
    
    # Agregar encabezados
    for key, value in extra_headers.items():
        headers += f"{key}: {value}\r\n"
    headers += "\r\n"  

    plain_message = headers + message

    reader, writer = None, None
    success = False

    try:
        reader, writer = await asyncio.open_connection(SMTP_SERVER, SMTP_PORT)
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

        writer.write(f"MAIL FROM:<{sender}>\r\n".encode())
        await writer.drain()
        await read_response(reader)

        for rec in recipients:
            writer.write(f"RCPT TO:<{rec}>\r\n".encode())
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
        success = True

    except Exception as e:
        logging.error(f"Error al enviar el correo: {e}")
    finally:
        if writer:
            writer.close()
            await writer.wait_closed()
        return success

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cliente SMTP simple (texto plano).")
    parser.add_argument("-p", "--port", type=int, required=True, help="Puerto SMTP.")
    parser.add_argument("-u", "--host", type=str, required=True, help="Host SMTP.")
    parser.add_argument("-f", "--from_mail", type=str, required=True, help="Correo del remitente.")
    parser.add_argument("-t", "--to_mail", type=str, required=True, help="Lista de correos destinatarios en formato JSON.")
    parser.add_argument("-s", "--subject", type=str, required=True, help="Asunto del correo.")
    parser.add_argument("-b", "--body", type=str, required=True, help="Cuerpo del correo.")
    parser.add_argument("-h", "--header", type=str, default="{}", help="Encabezados adicionales en formato JSON.")
    parser.add_argument("-P", "--password", type=str, default="default", help="Contraseña del remitente")

    args = parser.parse_args()

    # Parsear el parámetro to_mail
    try:
        recipients = json.loads(args.to_mail)
        if not isinstance(recipients, list):
            raise ValueError("to_mail debe ser una lista")
    except Exception as e:
        print(json.dumps({"status_code": 400, "message": f"Error al parsear to_mail: {e}"}))
        exit(1)

    # Parsear el parámetro header 
    try:
        extra_headers = json.loads(args.header)
        if not isinstance(extra_headers, dict):
            raise ValueError("header debe ser un diccionario")
    except Exception as e:
        print(json.dumps({"status_code": 400, "message": f"Error al parsear header: {e}"}))
        exit(1)

    SMTP_SERVER = args.host
    SMTP_PORT = args.port

    try:
        result = asyncio.run(send_email(args.from_mail, args.password,
                                        recipients, args.subject, args.body,
                                        extra_headers))
        if result:
            output = {"status_code": 333, "message": "Correo enviado correctamente."}
        else:
            output = {"status_code": 500, "message": "Error al enviar el correo."}
    except Exception as e:
        output = {"status_code": 500, "message": f"Excepción: {e}"}

    print(json.dumps(output))
