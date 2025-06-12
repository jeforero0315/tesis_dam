from flask import Flask, render_template, request, redirect, url_for, jsonify, session
import cx_Oracle
import os
import re
import subprocess
from datetime import datetime
from response_automation import send_alert_sms
from ldap_auth import authenticate_ldap_user

from authlib.integrations.flask_client import OAuth
from config import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET

app = Flask(__name__)
app.secret_key = 'clave_super_secreta_oauth2_simulada'

# OAuth2
oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# Conexión Oracle
def get_db_connection():
    try:
        connection = cx_Oracle.connect(user="admin_tesis", password="adminPassword", dsn="localhost:1521/XEPDB1")
        return connection
    except cx_Oracle.DatabaseError as e:
        print(f"[ERROR] Conexión Oracle: {e}")
        return None

# Login tradicional (BD o LDAP)
@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        connection = get_db_connection()
        if not connection:
            return "Error al conectar con la base de datos"

        cursor = connection.cursor()
        try:
            cursor.execute("SELECT user_type FROM admin_tesis.users WHERE email = :username", {'username': username})
            result = cursor.fetchone()

            if result:
                cursor.execute("""
                    SELECT user_type FROM admin_tesis.users
                    WHERE email = :username AND password = :password
                """, {'username': username, 'password': password})
                login_result = cursor.fetchone()

                if login_result:
                    session['user_type'] = login_result[0]
                    session['email'] = username
                    print(f"[BD] Autenticado: {username}")
                    return redirect(url_for('admin_dashboard'))
                else:
                    print(f"[BD] Contraseña incorrecta para {username}")
                    return "Contraseña incorrecta"
            else:
                if authenticate_ldap_user(username, password):
                    session['user_type'] = 'ldap_user'
                    session['email'] = username
                    print(f"[LDAP] Autenticado: {username}")
                    return redirect(url_for('admin_dashboard'))
                else:
                    print(f"[LDAP] Fallo autenticación de {username}")
                    return "Credenciales inválidas"
        except Exception as e:
            return f"Error autenticando: {e}"
        finally:
            cursor.close()
            connection.close()
    return render_template('login.html')

# Login con Google
@app.route('/login/google')
def login_google():
    redirect_uri = url_for('auth_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
def auth_callback():
    token = oauth.google.authorize_access_token()
    userinfo = oauth.google.get('https://openidconnect.googleapis.com/v1/userinfo').json()
    email = userinfo.get('email').strip().lower()  # <-- Asegura formato limpio

    connection = get_db_connection()
    if not connection:
        return "Error en conexión Oracle"

    cursor = connection.cursor()
    try:
        cursor.execute("SELECT user_type FROM admin_tesis.users WHERE LOWER(email) = :email", {'email': email})
        result = cursor.fetchone()

        if result:
            session['user_type'] = result[0]
            session['email'] = email
            print(f"[OAuth] Autenticado: {email}")
            return redirect(url_for('admin_dashboard'))
        else:
            print(f"[OAuth] Usuario no registrado: {email}")
            return "Usuario de Google no registrado"
    except Exception as e:
        return f"Error validando Google user: {e}"
    finally:
        cursor.close()
        connection.close()

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_type' in session:
        return render_template('admin_dashboard.html', role=session['user_type'], email=session['email'])
    return redirect(url_for('home'))

@app.route('/dashboard/access_control_monitoring')
def access_control_monitoring():
    if session.get('user_type') != 'admin':
        return render_template('403.html'), 403
    return render_template('access_control_monitoring_dashboard.html')

@app.route('/dashboard/incident')
def dashboard_incident():
    if session.get('user_type') != 'admin':
        return render_template('403.html'), 403

    incidentes = []
    log_file = r"C:\\Users\\jenif\\OneDrive\\Documentos\\Tesis\\logs\\incident_log.txt"
    if os.path.exists(log_file):
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        for i, line in enumerate(lines):
            if "Inyeccion detectada" in line:
                try:
                    usuario = re.search(r"Usuario: (.*?),", line).group(1).strip()
                    tabla = re.search(r"Tabla: (.+)", line).group(1).strip()
                    consulta = ""
                    fecha = ""
                    for j in range(i - 1, -1, -1):
                        if "Revisando:" in lines[j] and usuario in lines[j]:
                            consulta = lines[j].split("Revisando: ")[1].split(" |")[0].strip()
                            fecha = lines[j].split(" | ")[0].strip()
                            break
                    respaldo = tabla.replace(".", "_") + "_RESPALDO_" + fecha.replace("-", "").replace(":", "").replace(" ", "_")
                    incidentes.append({
                        'usuario': usuario,
                        'consulta': consulta,
                        'fecha': fecha,
                        'tabla_respaldo': respaldo,
                        'estado': 'Respaldado'
                    })
                except Exception as e:
                    print("Error procesando línea:", e)
    return render_template('incident_dashboard.html', incidentes=incidentes)

@app.route('/get_logs')
def get_logs():
    logs = []
    ip_addresses = []
    log_file = r"C:\\Users\\jenif\\OneDrive\\Documentos\\Tesis\\logs\\access_control_log.txt"
    if os.path.exists(log_file):
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            logs = f.readlines()
            for log in logs:
                if "IP: " in log:
                    ip_match = log.split("IP: ")[-1].split(",")[0].strip()
                    ip_addresses.append(ip_match)
    return jsonify({'logs': logs, 'ip_addresses': ip_addresses})

@app.route('/ejecutar_automated_response', methods=['POST'])
def ejecutar_automated_response():
    try:
        ruta_script = r"C:\\Users\\jenif\\OneDrive\\Documentos\\Tesis\\venv\\response_automation.py"
        ruta_python = r"C:\\Users\\jenif\\OneDrive\\Documentos\\Tesis\\venv\\Scripts\\python.exe"
        result = subprocess.run([ruta_python, ruta_script], capture_output=True, text=True)
        if result.returncode == 0:
            return jsonify({'success': True, 'message': 'Automatización ejecutada'})
        else:
            return jsonify({'success': False, 'message': result.stderr})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/notificar_equipo', methods=['POST'])
def notificar_equipo():
    try:
        send_alert_sms("🚨 Alerta: Se detectó una operación destructiva.")
        return jsonify({'success': True, 'message': 'Notificación enviada'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

if __name__ == "__main__":
    app.run(debug=True)
