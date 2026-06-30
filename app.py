"""
app.py — Servidor Flask con autenticación básica
Sirve el visor FRV protegido por usuario/contraseña.

Variables de entorno necesarias en Render:
  FRV_USER     - usuario para login
  FRV_PASSWORD - contraseña para login
"""

import os
from functools import wraps
from flask import Flask, send_from_directory, Response, request

app = Flask(__name__, static_folder="visor_frv", static_url_path="")

USUARIO  = os.environ.get("FRV_USER", "admin")
PASSWORD = os.environ.get("FRV_PASSWORD", "changeme")


def check_auth(username, password):
    return username == USUARIO and password == PASSWORD


def authenticate():
    return Response(
        "Acceso restringido. Ingresa las credenciales.", 401,
        {"WWW-Authenticate": 'Basic realm="FRV Privado"'}
    )


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


@app.route("/")
@requires_auth
def index():
    return send_from_directory("visor_frv", "index.html")


@app.route("/<path:filename>")
@requires_auth
def static_files(filename):
    return send_from_directory("visor_frv", filename)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
