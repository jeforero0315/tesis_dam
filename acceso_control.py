import logging
import socket
from datetime import datetime
import cx_Oracle
import sys
import os

# Definir la ruta de los logs
log_dir = r"C:\Users\jenif\OneDrive\Documentos\Tesis\logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Configurar el logger
logging.basicConfig(filename=os.path.join(log_dir, 'access_control_log.txt'), level=logging.INFO)

# Conexión a Oracle como SYSDBA
dsn = cx_Oracle.makedsn("localhost", 1521, service_name="XEPDB1")
try:
    conn = cx_Oracle.connect(user="sys", password="Familia1", dsn=dsn, mode=cx_Oracle.SYSDBA)
    logging.info("Conexión a Oracle establecida correctamente como SYSDBA.")
except cx_Oracle.DatabaseError as e:
    logging.error(f"Error al conectar a la base de datos: {e}")
    sys.exit(1)

# Obtener el rol del usuario
def get_user_role_from_db(user_name):
    cursor = conn.cursor()
    cursor.execute("""
        SELECT GRANTED_ROLE
        FROM DBA_ROLE_PRIVS
        WHERE GRANTEE = :user_name
    """, user_name=user_name)
    roles = cursor.fetchall()
    cursor.close()
    return roles[0][0] if roles else None

# Obtener IP del servidor
def get_ip_address():
    return socket.gethostbyname(socket.gethostname())

# Verificar privilegios por rol
def has_privileges(user_name, query):
    user_role = get_user_role_from_db(user_name)
    if not user_role:
        logging.warning(f"No se pudo determinar el rol del usuario {user_name}.")
        return False

    user_privileges = {
        'admin_tesis': ['FINANCIAL_DATA_USR.FINANCIAL_DATA'],
        'user_tesis': ['FINANCIAL_DATA_USR.FINANCIAL_DATA'],
    }

    if any(table in query for table in user_privileges.get(user_role, [])):
        return True
    else:
        logging.warning(f"Usuario {user_name} con rol {user_role} no tiene privilegios suficientes para ejecutar la consulta.")
        return False

# Registrar accesos (solo bloqueados)
def log_access(user_name, query_text, status):
    if status == 'Bloqueada':
        ip_address = get_ip_address()
        user_role = get_user_role_from_db(user_name)
        log_message = f"{datetime.now()} - Usuario: {user_name}, IP: {ip_address}, Rol: {user_role}, Consulta: {query_text}, Estatus: {status}\n"
        with open(os.path.join(log_dir, 'access_control_log.txt'), 'a') as file:
            file.write(log_message)
        logging.info(f"Acceso registrado: {log_message}")

# Auditoría de consultas normales (limita a 20)
def query_audit_logs():
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT id, user_name, query_text, timestamp
            FROM financial_data_audit_log
            ORDER BY id DESC
            FETCH FIRST 20 ROWS ONLY
        """)
        audit_logs = cursor.fetchall()
        logging.info(f"Se recuperaron {len(audit_logs)} registros de 'financial_data_audit_log'.")

        for _id, user_name, query_text, timestamp in audit_logs:
            status = 'Permitida' if has_privileges(user_name, query_text) else 'Bloqueada'
            log_access(user_name, query_text, status)

    except cx_Oracle.DatabaseError as e:
        logging.error(f"Error en auditoría de consultas: {e}")
    finally:
        cursor.close()

# Auditoría de operaciones DDL (columnas confirmadas)
def query_audit_logs_ddl():
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT user_name, operation, object_name, timestamp
            FROM audit_log
            ORDER BY timestamp DESC
            FETCH FIRST 20 ROWS ONLY
        """)
        audit_logs = cursor.fetchall()
        logging.info(f"Se recuperaron {len(audit_logs)} registros de 'audit_log'.")

        for user_name, operation, object_name, timestamp in audit_logs:
            query_text = f"{operation} sobre el objeto {object_name}"
            status = 'Permitida' if has_privileges(user_name, query_text) else 'Bloqueada'
            log_access(user_name, query_text, status)

    except cx_Oracle.DatabaseError as e:
        logging.error(f"Error en auditoría DDL: {e}")
    finally:
        cursor.close()

# Ejecutar todo
if __name__ == "__main__":
    query_audit_logs()
    query_audit_logs_ddl()
    conn.close()
