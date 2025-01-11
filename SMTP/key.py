from cryptography.fernet import Fernet

# Generar una clave de cifrado
key = Fernet.generate_key()

# Guardar la clave en un archivo
with open("secret.key", "wb") as key_file:
    key_file.write(key)

