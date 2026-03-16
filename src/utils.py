import os
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.fernet import Fernet

def cargar_llave_privada(ruta):
    """Carga una llave privada RSA desde un archivo PEM."""
    with open(ruta, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def cargar_llave_publica(ruta):
    """Carga una llave pública RSA desde un archivo PEM."""
    with open(ruta, 'rb') as f:
        return serialization.load_pem_public_key(f.read())

def obtener_relleno_rsa():
    """Retorna la configuración estándar de padding RSA-OAEP con SHA-256."""
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )

def generar_par_llaves(ruta_privada='keys/private_key.pem',
                       ruta_publica='keys/public_key.pem'):
    """Genera un par de llaves RSA 2048 y las guarda como archivos PEM."""
    os.makedirs('keys', exist_ok=True)
    llave_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(ruta_privada, 'wb') as f:
        f.write(llave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    llave_publica = llave_privada.public_key()
    with open(ruta_publica, 'wb') as f:
        f.write(llave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return llave_privada, llave_publica

def marca_tiempo():
    """Retorna la hora actual formateada como HH:MM:SS."""
    return datetime.now().strftime("%H:%M:%S")
