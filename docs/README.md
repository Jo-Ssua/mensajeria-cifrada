# Chat Seguro — Mensajería Cifrada sobre TCP

Aplicación de chat en red local con cifrado híbrido RSA + AES (Fernet).
Permite conectar múltiples clientes a un servidor central, con todo el
tráfico cifrado, verificable mediante WireShark.

## Arquitectura de seguridad

- **RSA 2048** — Intercambio seguro de la llave de sesión (handshake).
- **Fernet / AES-128-CBC + HMAC** — Cifrado de todos los mensajes en tránsito.
- **Cifrado independiente por cliente** — Cada cliente negocia su propia
  llave de sesión; el servidor re-cifra al retransmitir (hub-and-spoke).

## Estructura del proyecto
```text
MensajeriaEncriptada/
│
├── src/                        # Todo el código fuente
│   ├── server.py
│   ├── client.py
│   └── utils.py
│
├── config/                     # Configuración externa
│   └── config.ini
│
├── keys/                       # Generada automáticamente por utils.py
│   ├── private_key.pem        
│   └── public_key.pem
│
├── docs/                       # Documentación del proyecto
│   └── README.md
│
├── .gitignore
└── requirements.txt


```


## Requisitos

- Python 3.9+
- Librería `cryptography`

## Instalación

```bash
# 1. Crear y activar entorno virtual
python -m venv venv

# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate

# 2. Instalar dependencias
pip install -r requirements.txt

```


## Configuración de red

Edita `config/config.ini` antes de ejecutar:

```ini
[red]
host        = 0.0.0.0    # Interfaz del servidor (no cambiar)
puerto      = 5001        # Puerto TCP
ip_servidor = 127.0.0.1  # ← Cambiar a la IP local del servidor
                          #   (usar ipconfig en Windows / ip a en Linux)
[llaves]
ruta_llave_privada = keys/private_key.pem
ruta_llave_publica = keys/public_key.pem
```

## Ejecución

### 1. Iniciar el servidor (máquina A)

```bash
python src/server.py

El servidor generará las llaves RSA automáticamente si no existen y comenzará a escuchar conexiones entrantes. El panel lateral
mostrará los clientes conectados en tiempo real.


```

### 2. Iniciar clientes (máquinas B, C, ...)

```bash
python src/client.py

Al abrirse, el cliente pedirá un nombre de usuario mediante un diálogo. Luego se conectará al servidor configurado en config/config.ini.

Se puede abrir múltiples instancias de client.py en la misma máquina o en distintas máquinas de la misma red local.
```

