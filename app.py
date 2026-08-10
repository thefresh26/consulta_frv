"""
app.py — Servidor Flask con login por formulario y control de acceso por rol.
Sirve el visor FRV protegido por sesión. El rol determina qué campos de
avalúo se incluyen en /data.json.

El login ya NO valida contra un diccionario local de usuarios/contraseñas:
se valida contra Supabase Auth (el mismo proyecto que usan Vista_inmuebles_SAE
y Vista_Inmuebles), reutilizando las cuentas juridica2026 y comercial2026.
Así, la trazabilidad y el control de usuarios queda centralizado en un solo
lugar (Supabase) en vez de repartido en cada proyecto.

Variables de entorno necesarias en Render:
  SECRET_KEY                - clave para firmar la sesión de Flask
  SUPABASE_URL               - URL del proyecto Supabase
  SUPABASE_ANON_KEY          - anon key
  SUPABASE_SERVICE_ROLE_KEY  - service_role key (solo para guardar logs)
"""

import os
import json
import requests
from functools import wraps
from flask import Flask, send_from_directory, request, session, redirect, url_for, Response

app = Flask(__name__, static_folder="visor_frv", static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")

# Mapeo usuario corto -> correo real en Supabase Auth (mismo patrón que los
# otros visores, para que el login se siga sintiendo igual que antes).
USER_EMAILS = {
    "juridica2026":  "juridica2026@sae-inmuebles.app",
    "comercial2026": "comercial2026@sae-inmuebles.app",
}

CAMPOS_RESTRINGIDOS_COMERCIAL = [
    "VALOR AVALÚO",
    "AÑO AVALÚO",
    "TIPO AVALÚO",
    "FECHA AVALÚO",
    "TIENE AVALÚO",
    "VALOR AVALÚO COMERCIAL",
    "AÑO AVALÚO COMERCIAL",
    "FECHA AVALÚO COMERCIAL",
    "TIENE AVALÚO COMERCIAL",
    "CON AVALÚO COMERC.",
]

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


def obtener_ip_cliente():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr


def registrar_log(email, accion, detalle, ip=None):
    """Mejor esfuerzo: si falla el log, no interrumpe el uso normal de la app."""
    try:
        requests.post(
            f"{SUPABASE_URL}/rest/v1/logs_acceso_frv",
            headers={
                "apikey": SUPABASE_SERVICE_ROLE_KEY,
                "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
                "Content-Type": "application/json",
            },
            json={"usuario_email": email, "accion": accion, "detalle": detalle, "ip_address": ip},
            timeout=5,
        )
    except Exception:
        pass


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

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    email = USER_EMAILS.get(username, username)

    r = requests.post(
        f"{SUPABASE_URL}/auth/v1/token?grant_type=password",
        headers={"apikey": SUPABASE_ANON_KEY, "Content-Type": "application/json"},
        json={"email": email, "password": password},
        timeout=10,
    )

    if r.status_code == 200:
        data = r.json()
        user = data.get("user", {})
        rol = (user.get("user_metadata") or {}).get("role", "comercial")

        session["usuario"] = username
        session["email"] = email
        session["rol"] = rol

        registrar_log(email, "login", None, obtener_ip_cliente())
        return redirect(url_for("index"))

    error_html = '<div class="error">Usuario o contraseña incorrectos.</div>'
    return LOGIN_HTML.replace("__ERROR__", error_html), 401


@app.route("/logout")
def logout():
    detalle = request.args.get("motivo")
    if session.get("email"):
        registrar_log(
            session["email"],
            "logout_inactividad" if detalle == "inactividad" else "logout",
            None,
            obtener_ip_cliente(),
        )
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
            {k: v for k, v in registro.items() if k not in CAMPOS_RESTRINGIDOS_COMERCIAL}
            for registro in data
        ]

    registrar_log(session.get("email"), "consulta_datos", None, obtener_ip_cliente())
    return Response(json.dumps(data, ensure_ascii=False), mimetype="application/json")


@app.route("/<path:filename>")
@requires_auth
def static_files(filename):
    return send_from_directory("visor_frv", filename)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
