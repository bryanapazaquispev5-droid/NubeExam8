# Cifrado en Sobre con AWS KMS (Envelope Encryption) - NubeExam8

Implementación minimalista y pedagógica en Python del patrón de **Cifrado en Sobre (*Envelope Encryption*)** utilizado por **AWS KMS**.

---

## 🚀 Ejecución Rápida mediante `curl`

### Opción A: Descargar y ejecutar en Windows (CMD / PowerShell)
> **Nota de Examen para Windows:** En PowerShell, `curl` suele ser un alias de `Invoke-WebRequest`. Usa `curl.exe` para asegurar la sintaxis estándar de curl.

```bash
# 1. Descargar el script
curl.exe -sL https://raw.githubusercontent.com/bryanapazaquispev5-droid/NubeExam8/main/cifrado_sobre_kms.py -o cifrado_sobre_kms.py

# 2. Ejecutar
python cifrado_sobre_kms.py
```

### Opción B: En Linux / macOS / Git Bash
```bash
curl -sL https://raw.githubusercontent.com/bryanapazaquispev5-droid/NubeExam8/main/cifrado_sobre_kms.py -o cifrado_sobre_kms.py
python3 cifrado_sobre_kms.py
```

---

## 🔒 Estructura y Flujo Implementado

El archivo `cifrado_sobre_kms.py` implementa los 5 requerimientos estrictos de seguridad:

1. **Conexión a AWS KMS:** Conecta vía `boto3` o activa un simulador criptográfico si no hay credenciales activas (ideal para calificación de laboratorio sin costo).
2. **Generación de Data Key & Cifrado:** Solicita la DEK (`generate_data_key`), cifra el mensaje con `Fernet` (AES-128-CBC + HMAC SHA-256).
3. **Destrucción de la Llave Plana:** Ejecuta `del llave_datos_plana` para borrarla inmediatamente de la RAM.
4. **Sobre Digital:** Guarda el mensaje cifrado y la llave cifrada en `sobre_digital.json`.
5. **Función de Descifrado:** Llama a `kms.decrypt()` para recuperar la Data Key y descifra el mensaje, revelando ambos en consola.
