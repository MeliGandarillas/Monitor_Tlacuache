#!/usr/bin/env python3
"""Tlacuache: honeypot de SSH, Telnet y HTTP.

Como el tlacuache, que se hace el muerto, este servidor finge ser una
máquina descuidada. Nunca ejecuta lo que recibe: solo lo anota en una
bitácora SQLite para estudiarlo después.
"""
import argparse
import asyncio
import os
import re
import sqlite3
import time
from urllib.parse import parse_qs

import asyncssh

MAX_TEXTO = 256        # recorte de cualquier dato que llega de fuera
MAX_COMANDOS = 20      # comandos por sesión antes de colgar
TIEMPO_SESION = 60     # segundos de espera por línea
MAX_CONEXIONES = 200   # conexiones simultáneas de Telnet y HTTP

# Con estas contraseñas el señuelo "deja entrar" a un shell de mentiras,
# para ver qué comandos intentan. Con cualquier otra, rechaza.
CLAVES_DEBILES = {"123456", "admin", "root", "password", "1234", "12345", "toor"}

ANFITRION = "srv-web01"
PROMPT = f"root@{ANFITRION}:~# "
RESPUESTAS = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "pwd": "/root",
    "hostname": ANFITRION,
    "uname": f"Linux {ANFITRION} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
    "ls": "backup.tar.gz  notas.txt",
}

PAGINA = """<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>Panel de administración</title></head>
<body><h2>Panel de administración</h2>{aviso}
<form method="post" action="/login">
<p><input name="username" placeholder="Usuario"></p>
<p><input name="password" type="password" placeholder="Contraseña"></p>
<p><button>Entrar</button></p>
</form></body></html>"""

CONTROL = re.compile(r"[\x00-\x1f\x7f]")
TELNET_IAC = re.compile(rb"\xff[\xfb-\xfe].|\xff.")


def limpia(texto):
    """Deja el dato en una línea imprimible y de largo acotado."""
    if texto is None:
        return None
    return CONTROL.sub(" ", str(texto))[:MAX_TEXTO]


class Bitacora:
    def __init__(self, ruta):
        self.db = sqlite3.connect(ruta)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS eventos (
                   id INTEGER PRIMARY KEY,
                   ts REAL NOT NULL,
                   servicio TEXT NOT NULL,
                   ip TEXT NOT NULL,
                   tipo TEXT NOT NULL,      -- conexion, login, comando, peticion
                   usuario TEXT,
                   clave TEXT,
                   dato TEXT,
                   agente TEXT)"""
        )
        self.db.execute("CREATE INDEX IF NOT EXISTS por_ts ON eventos (ts)")
        self.db.commit()

    def anota(self, servicio, ip, tipo, usuario=None, clave=None, dato=None, agente=None):
        self.db.execute(
            "INSERT INTO eventos (ts, servicio, ip, tipo, usuario, clave, dato, agente)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (time.time(), servicio, ip, tipo, limpia(usuario), limpia(clave),
             limpia(dato), limpia(agente)),
        )
        self.db.commit()
        print(f"[{servicio}] {ip} {tipo} {limpia(usuario) or ''} {limpia(dato) or ''}", flush=True)


bitacora = None


def responde(comando):
    """Salida de mentiras: se busca en una tabla, no se ejecuta nada."""
    partes = comando.split()
    return RESPUESTAS.get(partes[0], "") if partes else ""


# ---------------------------------------------------------------- SSH

class ServidorSSH(asyncssh.SSHServer):
    def connection_made(self, conn):
        self.conn = conn
        self.ip = conn.get_extra_info("peername")[0]
        bitacora.anota("ssh", self.ip, "conexion")

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    async def validate_password(self, username, password):
        bitacora.anota("ssh", self.ip, "login", usuario=username, clave=password,
                       agente=self.conn.get_extra_info("client_version"))
        await asyncio.sleep(1)          # frena la fuerza bruta
        return password in CLAVES_DEBILES


async def sesion_ssh(proceso):
    ip = proceso.get_extra_info("peername")[0]
    if proceso.command:                 # ssh usuario@host "comando"
        bitacora.anota("ssh", ip, "comando", dato=proceso.command)
        salida = responde(proceso.command)
        if salida:
            proceso.stdout.write(salida + "\n")
        proceso.exit(0)
        return
    try:
        proceso.stdout.write(PROMPT)
        for _ in range(MAX_COMANDOS):
            try:
                linea = await asyncio.wait_for(proceso.stdin.readline(), TIEMPO_SESION)
            except asyncssh.TerminalSizeChanged:
                continue
            if not linea:
                break
            comando = linea.strip()
            if comando in ("exit", "logout"):
                break
            if comando:
                bitacora.anota("ssh", ip, "comando", dato=comando)
                salida = responde(comando)
                if salida:
                    proceso.stdout.write(salida + "\n")
            proceso.stdout.write(PROMPT)
    except (asyncio.TimeoutError, asyncssh.Error, OSError):
        pass
    proceso.exit(0)


# ------------------------------------------------------- Telnet y HTTP

activas = 0


def con_limite(manejador):
    """Atiende la conexión solo si no hay demasiadas abiertas."""
    async def envoltura(lector, escritor):
        global activas
        if activas >= MAX_CONEXIONES:
            escritor.close()
            return
        activas += 1
        try:
            await manejador(lector, escritor)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError,
                asyncio.LimitOverrunError, ConnectionError, ValueError, OSError):
            pass
        finally:
            activas -= 1
            escritor.close()
    return envoltura


async def lee_linea(lector):
    datos = await asyncio.wait_for(lector.readline(), TIEMPO_SESION)
    if not datos:
        raise ConnectionError("el otro lado colgó")
    return TELNET_IAC.sub(b"", datos).decode("utf-8", "replace").strip()


async def atiende_telnet(lector, escritor):
    ip = escritor.get_extra_info("peername")[0]
    bitacora.anota("telnet", ip, "conexion")
    escritor.write(f"\r\nUbuntu 22.04.3 LTS\r\n{ANFITRION} login: ".encode())
    usuario = await lee_linea(lector)
    escritor.write(b"Password: ")
    clave = await lee_linea(lector)
    bitacora.anota("telnet", ip, "login", usuario=usuario, clave=clave)
    await asyncio.sleep(1)
    if clave not in CLAVES_DEBILES:
        escritor.write(b"\r\nLogin incorrect\r\n")
        await escritor.drain()
        return
    escritor.write(("\r\n" + PROMPT).encode())
    for _ in range(MAX_COMANDOS):
        comando = await lee_linea(lector)
        if comando in ("exit", "logout"):
            break
        if comando:
            bitacora.anota("telnet", ip, "comando", dato=comando)
            salida = responde(comando)
            if salida:
                escritor.write((salida + "\r\n").encode())
        escritor.write(PROMPT.encode())
    await escritor.drain()


def primero(formulario, nombres):
    for nombre in nombres:
        if formulario.get(nombre):
            return formulario[nombre][0]
    return None


async def atiende_http(lector, escritor):
    ip = escritor.get_extra_info("peername")[0]
    cabecera = await asyncio.wait_for(lector.readuntil(b"\r\n\r\n"), 15)
    lineas = cabecera.decode("latin-1").split("\r\n")
    partes = lineas[0].split(" ")
    metodo = partes[0]
    ruta = partes[1] if len(partes) > 1 else ""
    campos = {}
    for linea in lineas[1:]:
        nombre, hay, valor = linea.partition(":")
        if hay:
            campos[nombre.strip().lower()] = valor.strip()
    largo = campos.get("content-length", "0")
    largo = min(int(largo), 4096) if largo.isdigit() else 0
    cuerpo = b""
    if largo:
        cuerpo = await asyncio.wait_for(lector.readexactly(largo), 15)
    agente = campos.get("user-agent")
    bitacora.anota("http", ip, "peticion", dato=f"{metodo} {ruta}", agente=agente)

    aviso = ""
    if metodo == "POST":
        formulario = parse_qs(cuerpo.decode("utf-8", "replace"))
        usuario = primero(formulario, ("username", "user", "log", "usuario", "email", "login"))
        clave = primero(formulario, ("password", "pass", "pwd", "clave"))
        if usuario or clave:
            bitacora.anota("http", ip, "login", usuario=usuario, clave=clave, agente=agente)
        aviso = "<p>Usuario o contraseña incorrectos.</p>"
    html = PAGINA.format(aviso=aviso).encode()
    escritor.write(
        b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\n"
        b"Content-Type: text/html; charset=utf-8\r\nConnection: close\r\n"
        + f"Content-Length: {len(html)}\r\n\r\n".encode() + html
    )
    await escritor.drain()


# ---------------------------------------------------------- arranque

async def principal(args):
    global bitacora
    bitacora = Bitacora(args.db)

    if not os.path.exists(args.clave_host):
        asyncssh.generate_private_key("ssh-ed25519").write_private_key(args.clave_host)
        os.chmod(args.clave_host, 0o600)

    await asyncssh.create_server(
        ServidorSSH, args.host, args.ssh,
        server_host_keys=[args.clave_host],
        process_factory=sesion_ssh,
        server_version="OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        login_timeout=30,
        errors="replace",
    )
    await asyncio.start_server(con_limite(atiende_telnet), args.host, args.telnet, limit=4096)
    await asyncio.start_server(con_limite(atiende_http), args.host, args.http, limit=8192)
    print(f"Tlacuache escuchando: ssh {args.ssh}, telnet {args.telnet}, http {args.http}",
          flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Honeypot de SSH, Telnet y HTTP")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--ssh", type=int, default=2222)
    p.add_argument("--telnet", type=int, default=2323)
    p.add_argument("--http", type=int, default=8081)
    p.add_argument("--db", default="tlacuache.db")
    p.add_argument("--clave-host", default="clave_host")
    try:
        asyncio.run(principal(p.parse_args()))
    except KeyboardInterrupt:
        pass
