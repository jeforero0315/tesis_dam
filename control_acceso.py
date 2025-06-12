import logging
import socket
from datetime import datetime
import cx_Oracle

# Configuración del logger para el control de acceso
logging.basicConfig(filename='logs/access_control_log.txt', level=logging.INFO)

# Conexión a Oracle
dsn = cx_Oracle.makedsn("localhost", 1521, service_name="XEPDB1")
try:
    conn = cx_Oracle.connect(user="system", password="Familia1", dsn=dsn)
    logging.info("Conexión a Oracle establecida correctamente.")
except cx_Oracle.DatabaseError as e:
    logging.error(f"Error al conectar a la base de datos: {e}")
    sys.exit(1)

# Función para obtener el rol del usuario desde la base de datos
def get_user_role_from_db(user_name):
    """
    Recupera el rol del usuario desde la base de datos utilizando la consulta
    SELECT GRANTED_ROLE FROM DBA_ROLE_PRIVS WHERE GRANTEE = :user_name
    """
    cursor = conn.cursor()
    cursor.execute("""
        SELECT GRANTED_ROLE
        FROM DBA_ROLE_PRIVS
        WHERE GRANTEE = :user_name
    """, user_name=user_name)
    
    roles = cursor.fetchall()
    cursor.close()

    if roles:
        return roles[0][0]  # Retornar el primer rol
    else:
        logging.warning(f"El usuario {user_name} no tiene roles asignados.")
        return None

# Función para obtener la dirección IP del servidor
def get_ip_address():
    return socket.gethostbyname(socket.gethostname())

# Función para verificar privilegios según el rol
def has_privileges(user_name, query):
    user_role = get_user_role_from_db(user_name)
    
    if not user_role:
        logging.warning(f"No se pudo determinar el rol del usuario {user_name}.")
        return False

    # Definir privilegios según el rol del usuario
    user_privileges = {
        'admin_tesis': ['FINANCIAL_DATA_USR.FINANCIAL_DATA'],  # admin tiene acceso completo
        'user_tesis': ['FINANCIAL_DATA_USR.FINANCIAL_DATA'],  # user tiene acceso solo a SELECT
    }

    # Verificar si el rol del usuario tiene acceso a la tabla indicada en la consulta
    if any(table in query for table in user_privileges.get(user_role, [])):
        return True
    else:
        logging.warning(f"Usuario {user_name} con rol {user_role} no tiene privilegios suficientes para ejecutar la consulta.")
        return False

# Función para registrar la actividad en el archivo de log
def log_access(user_name, query_text, status):
    """
    Registra la actividad del usuario en un archivo de texto.
    """
    ip_address = get_ip_address()
    user_role = get_user_role_from_db(user_name)
    log_message = f"{datetime.now()} - Usuario: {user_name}, IP: {ip_address}, Rol: {user_role}, Consulta: {query_text}, Estatus: {status}\n"
    
    # Registrar en el archivo
    with open('logs/access_control_log.txt', 'a') as file:
        file.write(log_message)
    logging.info(f"Acceso registrado: {log_message}")

# Función para recuperar registros de auditoría de consultas
def query_audit_logs():
    """
    Recupera los registros de la tabla de auditoría de consultas y ejecuta el control de acceso.
    """
    cursor = conn.cursor()
    try:
        # Recuperar registros de la tabla de auditoría (se asumirá que tienes una tabla como 'financial_data_audit_log')
        cursor.execute("""
            SELECT timestamp, user_name, query_text
            FROM SYS.financial_data_audit_log
            ORDER BY timestamp DESC
        """)
        audit_logs = cursor.fetchall()
        logging.info(f"Se recuperaron {len(audit_logs)} registros de auditoría de 'financial_data_audit_log'.")

        if not audit_logs:
            logging.info("No se encontraron registros en la auditoría de 'financial_data_audit_log'.")
        
        for log in audit_logs:
            timestamp = log[0]
            user_name = log[1]
            query_text = log[2]
            
            # Registrar acceso en el archivo
            status = 'Permitida' if has_privileges(user_name, query_text) else 'Bloqueada'
            log_access(user_name, query_text, status)

    except Exception as e:
        logging.error(f"Error al ejecutar la consulta de auditoría: {e}")
    finally:
        cursor.close()

# Ejecutar el ajuste de escalador y comenzar la escucha de consultas
if __name__ == "__main__":
    query_audit_logs()

# Cerrar la conexión a la base de datos
conn.close()
