import os
import sys
import shutil
import time
import ctypes
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ==========================================
# PARÁMETROS DE DETECCIÓN HEURÍSTICA
# ==========================================
RUTA_MONITOREO = r"C:\Users"        # Ruta a vigilar
DIR_CUARENTENA = r"C:\Cuarentena"   # Zona de aislamiento
UMBRAL_MODIFICACIONES = 5          # Sensibilidad de detección
VENTANA_TIEMPO = 3                  # Ventana en segundos

def es_administrador():
    """Verifica si el script se está ejecutando con permisos de Administrador."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

class ContencionRansomware(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.contador_eventos = []
        self.proceso_mitigado = False
        self.crear_cuarentena()

    def crear_cuarentena(self):
        if not os.path.exists(DIR_CUARENTENA):
            os.makedirs(DIR_CUARENTENA)

    def on_modified(self, event):
        if not event.is_directory:
            self.registrar_y_analizar()

    def on_created(self, event):
        if not event.is_directory:
            self.registrar_y_analizar()

    def registrar_y_analizar(self):
        if self.proceso_mitigado:
            return

        ahora = time.time()
        self.contador_eventos.append(ahora)
        self.contador_eventos = [t for t in self.contador_eventos if ahora - t <= VENTANA_TIEMPO]

        if len(self.contador_eventos) >= UMBRAL_MODIFICACIONES:
            print(f"\n🚨 [ANOMALÍA DETECTADA] Tasa crítica de modificaciones en el disco.")
            print(f"📊 Ráfaga: {len(self.contador_eventos)} archivos alterados en {VENTANA_TIEMPO}s.")
            self.ejecutar_mitigacion_heuristica()

    def ejecutar_mitigacion_heuristica(self):
        """Filtra procesos del sistema y elimina solo ejecutables de usuario sospechosos."""
        proceso_objetivo = None

        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pid = proc.info['pid']
                nombre = (proc.info['name'] or "").lower()
                ruta_exe = (proc.info['exe'] or "").lower()

                # FILTRO DE SEGURIDAD: Ignorar PIDs del sistema y procesos protegidos
                if pid < 1000 or pid == os.getpid():
                    continue

                # Ignorar procesos legítimos de Windows y del sistema
                if "windows" in ruta_exe or "system32" in ruta_exe or "registry" in nombre:
                    continue

                # Si el proceso se está ejecutando desde áreas de usuario (Temp, Desktop, Users, etc.)
                if ruta_exe and ("users" in ruta_exe or "temp" in ruta_exe or "appdata" in ruta_exe):
                    proceso_objetivo = proc
                    break

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if proceso_objetivo:
            try:
                pid = proceso_objetivo.info['pid']
                nombre = proceso_objetivo.info['name']
                ruta = proceso_objetivo.info['exe']

                # 1. Detener proceso
                proceso_objetivo.kill()
                self.proceso_mitigado = True
                print(f"⚡ [AUTÓNOMO] Proceso malicioso (PID: {pid} - {nombre}) DETENIDO.")

                # 2. Mover ejecutable a cuarentena
                if ruta and os.path.exists(ruta):
                    destino = os.path.join(DIR_CUARENTENA, f"{os.path.basename(ruta)}.quarantine")
                    shutil.move(ruta, destino)
                    print(f"🔒 [CUARENTENA] Ejecutable aislado exitosamente en: {destino}\n")

            except Exception as e:
                print(f"❌ Error al aislar proceso: {e}")
        else:
            print("⚠️ No se pudo determinar un proceso de usuario sospechoso en la ráfaga.")

def iniciar_detector():
    if not es_administrador():
        print("❌ ERROR: Este script requiere Permisos de Administrador.")
        print("👉 Por favor, abre la consola (CMD/PowerShell) como 'Ejecutar como Administrador'.")
        return

    print("=" * 65)
    print(" 🛡️  SISTEMA DE DETECCIÓN Y MITIGACIÓN AUTÓNOMA HEURÍSTICA".center(65))
    print("=" * 65)
    print(f" [*] Permisos de Administrador: CONFIRMADOS")
    print(f" [*] Estado: Vigilando {RUTA_MONITOREO} de forma autónoma...\n")

    handler = ContencionRansomware()
    observer = Observer()
    observer.schedule(handler, path=RUTA_MONITOREO, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    iniciar_detector()