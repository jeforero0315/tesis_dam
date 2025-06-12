import logging
import cx_Oracle
import re
from datetime import datetime
import socket


# Configuración del logger para el sistema de alertas
logging.basicConfig(filename='logs/incident_management_log.txt', level=logging.INFO)

# Función para enviar alertas (simulada)
def send_alert(alert_message, query):
    """
    envío de una alerta.
    """
    logging.info(f"ALERTA: {alert_message} - Consulta: {query}")

# Función para bloquear una consulta maliciosa
def block_query(query):
    """
    Bloquea la consulta si se detecta como maliciosa o destructiva.
    """
    logging.info(f"Consulta bloqueada: {query}")
    return False  # Bloquea la consulta

# Función para revertir una operación destructiva (DROP, DELETE, TRUNCATE)
def revert_changes(query):
    """
    Revertir una operación destructiva en caso de que se haya detectado un intento malicioso.
    """
    logging.warning(f"Revirtiendo operación destructiva: {query}")

    return True 

# Función para detectar posibles inyecciones SQL
def is_sql_injection(query):
    """
    Verifica si la consulta tiene patrones comunes de inyección SQL.
    """
    sql_injection_patterns = [
        r"(?i)(--|;|drop|insert|select|delete|update|union|exec|chr|mid|master|alter|grant|truncate|declare|cast)",  # Palabras clave comunes en inyecciones
        r"(?i)('|\")",  # Comillas para terminar la consulta y empezar una nueva
        r"(?i)admin",  # Palabra común en los intentos de obtener acceso privilegiado
    ]
    
    for pattern in sql_injection_patterns:
        if re.search(pattern, query):
            return True
    return False

# Función para detectar operaciones destructivas
def is_destructive(query):
    """
    Detecta operaciones destructivas como DROP, DELETE, TRUNCATE.
    """
    destructive_patterns = [
        r"(?i)\b(drop|delete|truncate)\b",  # Detecta palabras clave destructivas
    ]
    
    for pattern in destructive_patterns:
        if re.search(pattern, query):
            return True
    return False

# Función principal que integra la detección y respuesta ante anomalías
def automate_response(query, user_name):
    """
    Procesa la consulta y toma acciones automáticas si es maliciosa o destructiva.
    """
    logging.info(f"Procesando consulta: {query} de usuario {user_name}")
    
    # Detectamos si es una inyección SQL
    if is_sql_injection(query):
        send_alert("Posible inyección SQL detectada", query)
        return block_query(query)
    
    # Detectamos operaciones destructivas (DROP, DELETE, TRUNCATE)
    if is_destructive(query):
        send_alert("Operación destructiva bloqueada", query)
        revert_changes(query)  # Intentamos revertir cambios destructivos
        return block_query(query)
    
    logging.info(f"Consulta permitida: {query}")
    return True

# Conexión a Oracle (solo ejemplo, debes tener configurada la base de datos)
dsn = cx_Oracle.makedsn("localhost", 1521, service_name="XEPDB1")
try:
    conn = cx_Oracle.connect(user="system", password="Familia1", dsn=dsn)
    logging.info("Conexión a Oracle establecida correctamente.")
except cx_Oracle.DatabaseError as e:
    logging.error(f"Error al conectar a la base de datos: {e}")
    raise

# Función para obtener registros de auditoría de consultas
def query_audit_logs():
    cursor = conn.cursor()
    try:
        # Recuperar registros de la tabla 'financial_data_audit_log'
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
            logging.info(f"Consulta original: {query_text} realizada por {user_name} a las {timestamp}")
            
            # Procesamos la consulta y ejecutamos la automatización de respuestas
            automate_response(query_text, user_name)
    
    except Exception as e:
        logging.error(f"Error al ejecutar la consulta: {e}")
    finally:
        cursor.close()

# Función para escuchar las consultas y automatizar respuestas
def listen_for_queries():
    logging.info("Comenzando a escuchar las consultas...")
    query_audit_logs()

# Ejecutar el monitoreo de consultas y respuestas automáticas
if __name__ == "__main__":
    listen_for_queries()

# Cerrar la conexión a la base de datos
conn.close()
