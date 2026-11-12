#!/usr/bin/env python3
"""Panel de Tlacuache: lee la bitácora (solo lectura) y la muestra.

Escucha en 127.0.0.1 a propósito: en el servidor se abre con un túnel
SSH, nunca expuesto a internet.
"""
import argparse
import json
import os
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AQUI = os.path.dirname(os.path.abspath(__file__))
RUTA_DB = "tlacuache.db"
HORAS = 48


def resumen():
    db = sqlite3.connect(f"file:{RUTA_DB}?mode=ro", uri=True)
    uno = lambda sql, *a: db.execute(sql, a).fetchone()[0]
    top = lambda sql, *a: [{"valor": v, "veces": n} for v, n in db.execute(sql, a)]

    def mas(columna, tipo):
        return top(
            f"SELECT {columna}, COUNT(*) n FROM eventos WHERE tipo = ? AND {columna} <> ''"
            f" GROUP BY {columna} ORDER BY n DESC, {columna} LIMIT 10", tipo)

    ahora = int(time.time() // 3600)
    cuenta = dict(db.execute(
        "SELECT CAST(ts / 3600 AS INTEGER) h, COUNT(*) FROM eventos WHERE ts >= ? GROUP BY h",
        ((ahora - HORAS + 1) * 3600,)))
    datos = {
        "totales": {
            "eventos": uno("SELECT COUNT(*) FROM eventos"),
            "ips": uno("SELECT COUNT(DISTINCT ip) FROM eventos"),
            "logins": uno("SELECT COUNT(*) FROM eventos WHERE tipo = 'login'"),
            "comandos": uno("SELECT COUNT(*) FROM eventos WHERE tipo = 'comando'"),
        },
        "servicios": top("SELECT servicio, COUNT(*) n FROM eventos GROUP BY servicio ORDER BY n DESC"),
        "por_hora": [{"hora": h * 3600, "veces": cuenta.get(h, 0)}
                     for h in range(ahora - HORAS + 1, ahora + 1)],
        "usuarios": mas("usuario", "login"),
        "claves": mas("clave", "login"),
        "comandos": mas("dato", "comando"),
        "rutas": mas("dato", "peticion"),
        "ips": top("SELECT ip, COUNT(*) n FROM eventos GROUP BY ip ORDER BY n DESC, ip LIMIT 10"),
        "ultimos": [
            dict(zip(("ts", "servicio", "ip", "tipo", "usuario", "clave", "dato"), fila))
            for fila in db.execute(
                "SELECT ts, servicio, ip, tipo, usuario, clave, dato FROM eventos"
                " ORDER BY id DESC LIMIT 30")
        ],
    }
    db.close()
    return datos


class Panel(BaseHTTPRequestHandler):
    def responde(self, codigo, tipo, cuerpo):
        self.send_response(codigo)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(cuerpo)

    def do_GET(self):
        if self.path == "/":
            with open(os.path.join(AQUI, "panel.html"), "rb") as f:
                self.responde(200, "text/html; charset=utf-8", f.read())
        elif self.path == "/api/resumen":
            try:
                cuerpo = json.dumps(resumen()).encode()
            except sqlite3.Error as error:
                self.responde(503, "application/json", json.dumps({"error": str(error)}).encode())
                return
            self.responde(200, "application/json", cuerpo)
        else:
            self.responde(404, "text/plain; charset=utf-8", b"No existe")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Panel de Tlacuache")
    p.add_argument("--db", default="tlacuache.db")
    p.add_argument("--puerto", type=int, default=8080)
    args = p.parse_args()
    RUTA_DB = args.db
    print(f"Panel en http://127.0.0.1:{args.puerto}")
    ThreadingHTTPServer(("127.0.0.1", args.puerto), Panel).serve_forever()
