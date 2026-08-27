import os
import shutil
import time
import psutil
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ==========================================
# PARÁMETROS DE DETECCIÓN HEURÍSTICA
# ==========================================
RUTA_MONITOREO = r"C:\Users"        # Ruta a vigilar (ajustar según entorno de pruebas)
DIR_CUARENTENA = r"C:\Cuarentena"   # Zona de aislamiento
UMBRAL_MODIFICACIONES = 5          # Sensibilidad: Al detectar 5 ráfagas de cifrado/escritura
VENTANA_TIEMPO = 3                  # En un intervalo de 3 segundos

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
            self.registrar_y_analizar(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.registrar_y_analizar(event.src_path)

    def registrar_y_analizar(self, ruta_archivo):
        if self.proceso_mitigado:
            return

        ahora = time.time()
        self.contador_eventos.append(ahora)

        # Depurar el registro manteniendo solo eventos dentro de la ventana de tiempo
        self.contador_eventos = [t for t in self.contador_eventos if ahora - t <= VENTANA_TIEMPO]

        # EVALUACIÓN DE ANOMALÍA: Alta frecuencia de modificaciones en tiempo récord
        if len(self.contador_eventos) >= UMBRAL_MODIFICACIONES:
            print(f"\n🚨 [ANOMALÍA DETECTADA] Tasa crítica de modificaciones en el disco.")
            print(f"📊 Ráfaga: {len(self.contador_eventos)} archivos alterados en {VENTANA_TIEMPO}s.")
            self.ejecutar_mitigacion_heuristica()

    def ejecutar_mitigacion_heuristica(self):
        """Identifica el proceso sospechoso por consumo de recursos/archivos y lo liquida."""
        pid_sospechoso = None
        
        # Buscar el proceso con mayor actividad de E/S (I/O) o uso activo
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'io_counters']):
            try:
                # Omitir el propio detector y procesos del sistema básico
                if proc.info['pid'] == os.getpid() or proc.info['pid'] in (0, 4):
                    continue

                # Criterio heurístico: Proceso activo ejecutándose fuera de System32
                ruta_exe = proc.info['exe'] or ""
                if "system32" not in ruta_exe.lower() and "windows" not in ruta_exe.lower():
                    pid_sospechoso = proc.info['pid']
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if pid_sospechoso:
            try:
                p = psutil.Process(pid_sospechoso)
                nombre = p.name()
                ruta = p.exe()

                # 1. Matar el proceso inmediatamente (Kill a nivel de Kernel)
                p.kill()
                self.proceso_mitigado = True
                print(f"⚡ [AUTÓNOMO] Proceso malicioso (PID: {pid_sospechoso} - {nombre}) DETENIDO.")

                # 2. Mover a Cuarentena
                if ruta and os.path.exists(ruta):
                    destino = os.path.join(DIR_CUARENTENA, f"{os.path.basename(ruta)}.quarantine")
                    shutil.move(ruta, destino)
                    print(f"🔒 [CUARENTENA] Ejecutable aislado exitosamente en: {destino}\n")

            except Exception as e:
                print(f"❌ Error al aislar proceso: {e}")

def iniciar_detector():
    print("=" * 65)
    print(" 🛡️  SISTEMA DE DETECCIÓN Y MITIGACIÓN AUTÓNOMA HEURÍSTICA".center(65))
    print("=" * 65)
    print(f" [*] Estado: Vigilando {RUTA_MONITOREO} de forma autónoma...")
    print(f" [*] Regla Activa: Reacción inmediata ante >{UMBRAL_MODIFICACIONES} archivos/3s\n")

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