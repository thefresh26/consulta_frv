"""
app.py — Servidor Flask con login por formulario y control de acceso por rol.
Sirve el visor FRV protegido por sesión. El rol determina qué campos de
avalúo se incluyen en /data.json.

Variables de entorno necesarias en Render:
  SECRET_KEY - clave secreta para firmar la sesión de Flask
"""

import os
import json
from functools import wraps
from flask import Flask, send_from_directory, request, session, redirect, url_for, Response

app = Flask(__name__, static_folder="visor_frv", static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

USUARIOS = {
    "juridica2026":  {"password": "2026", "rol": "juridica"},
    "comercial2026": {"password": "2026", "rol": "comercial"},
}

CAMPOS_RESTRINGIDOS = ["VALOR AVALÚO", "AÑO AVALÚO"]

LOGIN_HTML = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>FRV — Iniciar sesión</title>
<style>
  body { font-family: system-ui, sans-serif; background:#0f172a; color:#e2e8f0; display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }
  form { background:#1e293b; padding:2rem 2.5rem; border-radius:12px; box-shadow:0 10px 30px rgba(0,0,0,.4); width:280px; }
  h1 { font-size:1.1rem; margin:0 0 1.2rem; }
  label { display:block; font-size:.85rem; margin:.6rem 0 .2rem; color:#94a3b8; }
  input { width:100%; box-sizing:border-box; padding:.5rem .6rem; border-radius:6px; border:1px solid #334155; background:#0f172a; color:#e2e8f0; }
  button { margin-top:1.2rem; width:100%; padding:.6rem; border:none; border-radius:6px; background:#2563eb; color:#fff; font-weight:600; cursor:pointer; }
  button:hover { background:#1d4ed8; }
  .error { color:#f87171; font-size:.85rem; margin-top:.8rem; }
</style>
</head>
<body>
<form method="post" action="/login">
  <h1>Acceso FRV</h1>
  <label for="username">Usuario</label>
  <input id="username" name="username" type="text" autocomplete="username" required autofocus>
  <label for="password">Contraseña</label>
  <input id="password" name="password" type="password" autocomplete="current-password" required>
  <button type="submit">Entrar</button>
  __ERROR__
</form>
</body>
</html>
"""


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "rol" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return LOGIN_HTML.replace("__ERROR__", "")

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    usuario = USUARIOS.get(username)

    if usuario and usuario["password"] == password:
        session["usuario"] = username
        session["rol"] = usuario["rol"]
        return redirect(url_for("index"))

    error_html = '<div class="error">Usuario o contraseña incorrectos.</div>'
    return LOGIN_HTML.replace("__ERROR__", error_html), 401


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@requires_auth
def index():
    return send_from_directory("visor_frv", "index.html")


@app.route("/data.json")
@requires_auth
def data_json():
    with open(os.path.join("visor_frv", "data.json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    if session.get("rol") == "comercial":
        data = [
            {k: v for k, v in registro.items() if k not in CAMPOS_RESTRINGIDOS}
            for registro in data
        ]

    return Response(json.dumps(data, ensure_ascii=False), mimetype="application/json")


@app.route("/<path:filename>")
@requires_auth
def static_files(filename):
    return send_from_directory("visor_frv", filename)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
