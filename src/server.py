import os
import socket
import threading
import configparser
import tkinter as tk
from tkinter import scrolledtext
from cryptography.fernet import Fernet
import utils

config = configparser.ConfigParser()
config.read('config/config.ini')
HOST               = config['red']['host']
PORT               = int(config['red']['puerto'])
RUTA_LLAVE_PRIVADA = config['llaves']['ruta_llave_privada']
RUTA_LLAVE_PUBLICA = config['llaves']['ruta_llave_publica']


class ServidorChat:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Seguro — Servidor")
        self.root.configure(bg='#1e1e2e')

        # ── Layout: chat (izq) + usuarios (der) ──
        marco = tk.Frame(root, bg='#1e1e2e')
        marco.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        marco_chat = tk.Frame(marco, bg='#1e1e2e')
        marco_chat.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.area_chat = scrolledtext.ScrolledText(
            marco_chat, state=tk.DISABLED, height=22,
            bg='#181825', fg='#cdd6f4', font=('Consolas', 10),
            insertbackground='white', relief=tk.FLAT
        )
        self.area_chat.pack(fill=tk.BOTH, expand=True)

        self.placeholder = "Escribe un mensaje..."
        self.entrada_msg = tk.Entry(
            marco_chat, bg='#313244', fg='#cdd6f4',
            insertbackground='white', font=('Consolas', 10), relief=tk.FLAT
        )
        self.entrada_msg.insert(0, self.placeholder)
        self.entrada_msg.pack(fill=tk.X, pady=(6, 0))
        self.entrada_msg.bind("<FocusIn>",  self.limpiar_placeholder)
        self.entrada_msg.bind("<FocusOut>", self.añadir_placeholder)
        self.entrada_msg.bind("<Return>",   self.enviar_mensaje)

        # ── Panel lateral de usuarios ──
        marco_usuarios = tk.Frame(marco, bg='#1e1e2e', width=160)
        marco_usuarios.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        marco_usuarios.pack_propagate(False)

        tk.Label(
            marco_usuarios, text="Conectados",
            bg='#1e1e2e', fg='#89b4fa', font=('Consolas', 10, 'bold')
        ).pack(pady=(0, 4))

        self.lista_usuarios = tk.Listbox(
            marco_usuarios, bg='#181825', fg='#a6e3a1',
            font=('Consolas', 10), selectbackground='#313244',
            borderwidth=0, highlightthickness=0
        )
        self.lista_usuarios.pack(fill=tk.BOTH, expand=True)

        # ── Estado interno ──
        self.clientes      = {}   # {conn: {'cifrador': Fernet, 'addr': tuple, 'nombre': str}}
        self.lock_clientes = threading.Lock()
        self.llave_privada = None

        threading.Thread(target=self.iniciar_servidor, daemon=True).start()

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

    def actualizar_panel_usuarios(self):
        self.lista_usuarios.delete(0, tk.END)
        with self.lock_clientes:
            for info in self.clientes.values():
                self.lista_usuarios.insert(tk.END, f"● {info['nombre']}")

    # ─────────────────── Servidor ───────────────────

    def iniciar_servidor(self):
        if not os.path.exists(RUTA_LLAVE_PRIVADA):
            self.registrar("[*] Generando par de llaves RSA...")
            utils.generar_par_llaves(RUTA_LLAVE_PRIVADA, RUTA_LLAVE_PUBLICA)
            self.registrar("[*] Llaves generadas correctamente.")

        self.llave_privada = utils.cargar_llave_privada(RUTA_LLAVE_PRIVADA)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen(5)
            self.registrar(f"[{utils.marca_tiempo()}] Escuchando en {HOST}:{PORT}...")
            while True:
                conn, addr = s.accept()
                threading.Thread(
                    target=self.manejar_cliente,
                    args=(conn, addr),
                    daemon=True
                ).start()

    def manejar_cliente(self, conn, addr):
        nombre = f"{addr[0]}:{addr[1]}"
        try:
            # Handshake RSA
            with open(RUTA_LLAVE_PUBLICA, 'rb') as f:
                conn.sendall(f.read())

            llave_sesion_cifrada = conn.recv(512)
            llave_sesion = self.llave_privada.decrypt(
                llave_sesion_cifrada, utils.obtener_relleno_rsa()
            )
            cifrador = Fernet(llave_sesion)

            # Primer mensaje: nombre de usuario
            datos = conn.recv(4096)
            primer_msg = cifrador.decrypt(datos).decode('utf-8')
            if primer_msg.startswith('__NOMBRE__:'):
                nombre = primer_msg.split(':', 1)[1].strip()

            with self.lock_clientes:
                self.clientes[conn] = {'cifrador': cifrador, 'addr': addr, 'nombre': nombre}

            self.registrar(f"[{utils.marca_tiempo()}] ✔ {nombre} se conectó  |  activos: {len(self.clientes)}")
            self.root.after(0, self.actualizar_panel_usuarios)
            self.difundir(f"[{utils.marca_tiempo()}] 🔔 {nombre} entró al chat.", excluir=conn)

            # Loop principal
            while True:
                datos = conn.recv(4096)
                if not datos:
                    break
                msg = cifrador.decrypt(datos).decode('utf-8')
                if msg == '__EXIT__':
                    break
                self.registrar(f"[{utils.marca_tiempo()}] {nombre}: {msg}")
                self.difundir(f"[{utils.marca_tiempo()}] {nombre}: {msg}", excluir=conn)

        except Exception as e:
            self.registrar(f"[!] Error con {nombre}: {e}")
        finally:
            with self.lock_clientes:
                self.clientes.pop(conn, None)
            conn.close()
            self.registrar(f"[{utils.marca_tiempo()}] ✖ {nombre} se desconectó  |  activos: {len(self.clientes)}")
            self.root.after(0, self.actualizar_panel_usuarios)
            self.difundir(f"[{utils.marca_tiempo()}] 🔔 {nombre} salió del chat.")

    # ─────────────────── Broadcast ───────────────────

    def difundir(self, msg, excluir=None):
        """Re-cifra el mensaje con la llave de sesión de cada destinatario."""
        fallidos = []
        with self.lock_clientes:
            for conn, info in self.clientes.items():
                if conn is excluir:
                    continue
                try:
                    conn.sendall(info['cifrador'].encrypt(msg.encode('utf-8')))
                except Exception:
                    fallidos.append(conn)
            for conn in fallidos:
                self.clientes.pop(conn, None)

    def enviar_mensaje(self, event=None):
        msg = self.entrada_msg.get()
        if msg and msg != self.placeholder:
            texto = f"[{utils.marca_tiempo()}] [Servidor]: {msg}"
            self.difundir(texto)
            self.registrar(f"[{utils.marca_tiempo()}] Tú (Servidor): {msg}")
            self.entrada_msg.delete(0, tk.END)


if __name__ == '__main__':
    root = tk.Tk()
    app = ServidorChat(root)
    root.mainloop()
