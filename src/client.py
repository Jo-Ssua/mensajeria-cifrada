import socket
import threading
import configparser
import tkinter as tk
from tkinter import scrolledtext, simpledialog
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import utils

config = configparser.ConfigParser()
config.read('config/config.ini')
IP_SERVIDOR = config['red']['ip_servidor']
PORT        = int(config['red']['puerto'])


class ClienteChat:
    def __init__(self, root):
        self.root = root
        self.root.configure(bg='#1e1e2e')

        # Pedir nombre antes de mostrar la ventana principal
        self.nombre = simpledialog.askstring(
            "Identificación", "¿Con qué nombre quieres aparecer en el chat?",
            parent=root
        ) or "Anónimo"
        self.root.title(f"Chat Seguro — {self.nombre}")

        self.area_chat = scrolledtext.ScrolledText(
            root, state=tk.DISABLED, height=22,
            bg='#181825', fg='#cdd6f4', font=('Consolas', 10),
            insertbackground='white', relief=tk.FLAT
        )
        self.area_chat.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.placeholder = "Escribe un mensaje..."
        self.entrada_msg = tk.Entry(
            root, bg='#313244', fg='#cdd6f4',
            insertbackground='white', font=('Consolas', 10), relief=tk.FLAT
        )
        self.entrada_msg.insert(0, self.placeholder)
        self.entrada_msg.pack(padx=10, pady=(0, 10), fill=tk.X)
        self.entrada_msg.bind("<FocusIn>",  self.limpiar_placeholder)
        self.entrada_msg.bind("<FocusOut>", self.añadir_placeholder)
        self.entrada_msg.bind("<Return>",   self.enviar_mensaje)

        self.cifrador = None
        self.sock     = None
        self.root.protocol("WM_DELETE_WINDOW", self.cerrar)

        threading.Thread(target=self.conectar, daemon=True).start()

    # ─────────────────── UI helpers ───────────────────

    def limpiar_placeholder(self, event):
        if self.entrada_msg.get() == self.placeholder:
            self.entrada_msg.delete(0, tk.END)

    def añadir_placeholder(self, event):
        if not self.entrada_msg.get():
            self.entrada_msg.insert(0, self.placeholder)

    def registrar(self, msg):
        self.area_chat.config(state=tk.NORMAL)
        self.area_chat.insert(tk.END, msg + "\n")
        self.area_chat.config(state=tk.DISABLED)
        self.area_chat.yview(tk.END)

    # ─────────────────── Conexión ───────────────────

    def conectar(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((IP_SERVIDOR, PORT))
            self.registrar(f"[{utils.marca_tiempo()}] ✔ Conectado a {IP_SERVIDOR}:{PORT}")

            # Handshake RSA
            pk_bytes     = self.sock.recv(1024)
            llave_publica = serialization.load_pem_public_key(pk_bytes)
            llave_sesion  = Fernet.generate_key()
            self.cifrador  = Fernet(llave_sesion)
            self.sock.sendall(
                llave_publica.encrypt(llave_sesion, utils.obtener_relleno_rsa())
            )

            # Enviar nombre de usuario como primer mensaje cifrado
            self.sock.sendall(
                self.cifrador.encrypt(f"__NOMBRE__:{self.nombre}".encode('utf-8'))
            )
            self.registrar(f"[{utils.marca_tiempo()}] 🔒 Canal seguro establecido como '{self.nombre}'")

            # Loop de recepción
            while True:
                datos = self.sock.recv(4096)
                if not datos:
                    break
                msg = self.cifrador.decrypt(datos).decode('utf-8')
                self.registrar(msg)

        except Exception as e:
            self.registrar(f"[!] Error: {e}")

    # ─────────────────── Envío ───────────────────

    def enviar_mensaje(self, event=None):
        msg = self.entrada_msg.get()
        if self.cifrador and self.sock and msg and msg != self.placeholder:
            self.sock.sendall(self.cifrador.encrypt(msg.encode('utf-8')))
            self.registrar(f"[{utils.marca_tiempo()}] Tú: {msg}")
            self.entrada_msg.delete(0, tk.END)

    def cerrar(self):
        if self.cifrador and self.sock:
            try:
                self.sock.sendall(self.cifrador.encrypt(b'__EXIT__'))
            except Exception:
                pass
        self.root.destroy()


if __name__ == '__main__':
    root = tk.Tk()
    app = ClienteChat(root)
    root.mainloop()
