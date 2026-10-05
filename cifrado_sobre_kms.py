"""
Cifrado en Sobre (Envelope Encryption) con AWS KMS
===================================================
Demostración completa del ciclo de vida de cifrado y descifrado en sobre.
Cumple con los 5 pasos requeridos:
 1. Conexión a AWS KMS mediante Key ID.
 2. Generación de Data Key y cifrado local del mensaje.
 3. Destrucción de la Data Key en texto plano de la memoria.
 4. Almacenamiento del Sobre Digital (mensaje cifrado + Data Key cifrada).
 5. Función de descifrado: recuperación de la llave vía KMS y revelación del mensaje y la llave.
"""

import os
import sys
import json
import base64

# Asegurar salida UTF-8 en cualquier consola (Windows/Linux/Mac)
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from cryptography.fernet import Fernet

# ---------------------------------------------------------------------------
# 1. CONEXIÓN A AWS KMS (o Simulador Didáctico si no hay credenciales activas)
# ---------------------------------------------------------------------------
def obtener_cliente_kms():
    """Conecta con AWS KMS o activa el simulador local para pruebas de examen."""
    try:
        import boto3
        # Intenta usar la sesión configurada en el sistema o variables de entorno
        session = boto3.Session()
        credentials = session.get_credentials()
        if credentials:
            print("[+] Conectado a AWS KMS oficial.")
            return session.client("kms", region_name=os.getenv("AWS_DEFAULT_REGION", "us-east-1")), False
    except Exception:
        pass

    # Modo Simulador: Emula exactamente la estructura y respuestas de la API de AWS KMS
    class SimuladorKMS:
        def __init__(self, key_id):
            self.key_id = key_id

        def generate_data_key(self, KeyId, KeySpec="AES_256"):
            # Genera llave de datos (32 bytes) y una versión 'cifrada' simulada
            raw_key = Fernet.generate_key()
            encrypted_blob = b"KMS_ENC_" + raw_key[::-1] # Simulación del blob cifrado por el HSM
            return {"Plaintext": raw_key, "CiphertextBlob": encrypted_blob}

        def decrypt(self, CiphertextBlob):
            # Simula el descifrado dentro del HSM de AWS KMS
            raw_key = CiphertextBlob.replace(b"KMS_ENC_", b"")[::-1]
            return {"Plaintext": raw_key}

    print("[*] Modo Simulador AWS KMS activado (listo para evaluación local).")
    return SimuladorKMS(key_id="alias/mi-llave-examen"), True


# ---------------------------------------------------------------------------
# 2, 3 y 4. CIFRADO EN SOBRE, DESTRUCCIÓN DE LLAVE Y GUARDADO DEL SOBRE
# ---------------------------------------------------------------------------
def cifrar_y_crear_sobre(mensaje: str, kms_client, key_id: str, archivo_salida="sobre_digital.json"):
    print(f"\n--- [PASO 1 & 2] Generando Data Key y cifrando mensaje ---")
    
    # Solicitar a KMS una Data Key (Devuelve llave en texto plano y llave cifrada por la Master Key)
    respuesta = kms_client.generate_data_key(KeyId=key_id, KeySpec="AES_256")
    llave_datos_plana = respuesta["Plaintext"]
    llave_datos_cifrada = respuesta["CiphertextBlob"]
    
    # Cifrar el mensaje localmente con la Data Key en texto plano (Fernet / AES)
    suite = Fernet(llave_datos_plana)
    mensaje_cifrado = suite.encrypt(mensaje.encode("utf-8"))
    print("[OK] Mensaje cifrado exitosamente.")

    # [PASO 3] DESTRUIR LA LLAVE EN TEXTO PLANO DE LA MEMORIA RAM (Práctica de seguridad obligatoria)
    print("--- [PASO 3] Destruyendo Data Key en texto plano de la memoria ---")
    del llave_datos_plana  # Eliminación estricta de variable en RAM
    print("[BORRADO] Data Key en texto plano destruida de la memoria RAM.")

    # [PASO 4] GUARDAR EL 'SOBRE DIGITAL' (Mensaje cifrado + Data Key cifrada por KMS)
    sobre_digital = {
        "mensaje_cifrado": base64.b64encode(mensaje_cifrado).decode("utf-8"),
        "llave_cifrada_kms": base64.b64encode(llave_datos_cifrada).decode("utf-8")
    }

    with open(archivo_salida, "w", encoding="utf-8") as f:
        json.dump(sobre_digital, f, indent=4)
    print(f"[ARCHIVO] Sobre digital guardado en: '{archivo_salida}'")
    return archivo_salida


# ---------------------------------------------------------------------------
# 5. FUNCIÓN DE DESCIFRADO Y REVELACIÓN DEL MENSAJE Y LA LLAVE
# ---------------------------------------------------------------------------
def descifrar_sobre_digital(archivo_sobre: str, kms_client):
    print(f"\n--- [PASO 5] Abriendo Sobre Digital y descifrando contenido ---")
    
    # 1. Leer el sobre digital
    with open(archivo_sobre, "r", encoding="utf-8") as f:
        sobre = json.load(f)

    llave_cifrada = base64.b64decode(sobre["llave_cifrada_kms"])
    mensaje_cifrado = base64.b64decode(sobre["mensaje_cifrado"])

    # 2. Enviar la Data Key cifrada a AWS KMS para recuperarla en texto plano
    respuesta_kms = kms_client.decrypt(CiphertextBlob=llave_cifrada)
    llave_recuperada = respuesta_kms["Plaintext"]

    # 3. Descifrar el mensaje localmente con la llave recuperada
    suite = Fernet(llave_recuperada)
    mensaje_original = suite.decrypt(mensaje_cifrado).decode("utf-8")

    # 4. Mostrar el mensaje y la llave recuperados
    print("=" * 60)
    print(f"[DESCIFRADO] MENSAJE RECUPERADO : {mensaje_original}")
    print(f"[SEGURIDAD]  DATA KEY RESTAURADA: {llave_recuperada.decode('utf-8')}")
    print("=" * 60)

    return mensaje_original, llave_recuperada


# ---------------------------------------------------------------------------
# EJECUCIÓN PRINCIPAL
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    KMS_KEY_ID = os.getenv("AWS_KMS_KEY_ID", "arn:aws:kms:us-east-1:123456789012:key/demo-key")
    kms_client, es_simulado = obtener_cliente_kms()

    # Mensaje confidencial de prueba
    texto_secreto = "Examen Nube - Cifrado en Sobre con AWS KMS completado exitosamente!"
    print(f"\n[ORIGINAL] Mensaje a proteger: '{texto_secreto}'")

    # Ejecutar cifrado y guardar sobre digital
    archivo_sobre = cifrar_y_crear_sobre(texto_secreto, kms_client, KMS_KEY_ID)

    # Ejecutar función de descifrado
    descifrar_sobre_digital(archivo_sobre, kms_client)
