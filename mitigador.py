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
UMBRAL_MODIFICACIONES = 5          # Sensibilidad (5 cambios)
VENTANA_TIEMPO = 2                  # Intervalo en segundos (2s)

# Lista blanca para evitar falsos positivos de procesos del sistema/sincronización
LISTA_BLANCA = ["onedrive.exe", "explorer.exe", "svchost.exe", "searchhost.exe"]

def es_administrador():
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
        proceso_objetivo = None

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                pid = proc.info['pid']
                nombre = (proc.info['name'] or "").lower()
                cmdline = " ".join(proc.info['cmdline'] or []).lower()

                # Ignorar PIDs del sistema y la lista blanca
                if pid < 1000 or pid == os.getpid() or nombre in LISTA_BLANCA:
                    continue

                # DETECCIÓN CLAVE: Si el proceso es Python ejecutando el script de cifrado
                if "python.exe" in nombre or "pythonw.exe" in nombre:
                    # Verificar que no sea el mismo detector
                    if "detector_autonomo" not in cmdline:
                        proceso_objetivo = proc
                        break

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if proceso_objetivo:
            try:
                pid = proceso_objetivo.info['pid']
                nombre = proceso_objetivo.info['name']
                cmd = " ".join(proceso_objetivo.info['cmdline'] or [])

                # 1. Detener inmediatamente la instancia de Python que ejecuta el ransomware
                proceso_objetivo.kill()
                self.proceso_mitigado = True
                print(f"⚡ [AUTÓNOMO] Proceso malicioso detectado y DETENIDO (PID: {pid} - {nombre}).")
                print(f"📌 Comando neutralizado: {cmd}")

                # 2. Intentar mover el archivo .py detectado a cuarentena
                for arg in proceso_objetivo.info['cmdline']:
                    if arg.endswith(".py") and os.path.exists(arg) and "detector" not in arg:
                        destino = os.path.join(DIR_CUARENTENA, f"{os.path.basename(arg)}.quarantine")
                        shutil.move(arg, destino)
                        print(f"🔒 [CUARENTENA] Script Python aislado en: {destino}\n")
                        break

            except Exception as e:
                print(f"❌ Error al mitigar el proceso: {e}")
        else:
            print("⚠️ No se identificó una instancia sospechosa de Python en la ráfaga.")

def iniciar_detector():
    if not es_administrador():
        print("❌ ERROR: Este script requiere Permisos de Administrador.")
        print("👉 Ejecuta la consola (CMD) como 'Ejecutar como Administrador'.")
        return

    print("=" * 65)
    print(" 🛡️  SISTEMA DE DETECCIÓN Y MITIGACIÓN AUTÓNOMA HEURÍSTICA".center(65))
    print("=" * 65)
    print(f" [*] Estado: Vigilando {RUTA_MONITOREO} de forma autónoma...")
    print(f" [*] Regla Activa: Intercepción de scripts o procesos en ráfaga\n")

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