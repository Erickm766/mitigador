import os
import shutil
import time
import psutil
from pathlib import Path
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ==========================================
# CONFIGURACIÓN DEL DETECTOR AUTÓNOMO
# ==========================================
RUTA_MONITOREO = r"C:\Users"        # Directorio a supervisar
DIR_CUARENTENA = r"C:\Cuarentena"   # Zona de aislamiento
UMBRAL_MODIFICACIONES = 10         # Máximo de archivos modificados
VENTANA_TIEMPO = 2                  # Segundos para evaluar la tasa de modificaciones

class MonitorComportamiento(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        # Registro de eventos: {pid: [timestamp1, timestamp2, ...]}
        self.registro_actividad = defaultdict(list)
        self.procesos_mitigados = set()
        self.crear_cuarentena()

    def crear_cuarentena(self):
        if not os.path.exists(DIR_CUARENTENA):
            os.makedirs(DIR_CUARENTENA)

    def on_modified(self, event):
        if event.is_directory:
            return
        self.analizar_evento_heuristico(event.src_path)

    def on_created(self, event):
        if event.is_directory:
            return
        self.analizar_evento_heuristico(event.src_path)

    def analizar_evento_heuristico(self, ruta_archivo):
        """Analiza qué proceso está interactuando con el archivo en tiempo real."""
        ahora = time.time()
        
        # Identificar el proceso responsable mediante inspección de handles abiertos
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pid = proc.info['pid']
                
                # Ignorar el propio detector y procesos críticos del sistema
                if pid == os.getpid() or pid in self.procesos_mitigados:
                    continue

                # Evaluar archivos abiertos por el proceso
                for open_file in proc.open_files():
                    if open_file.path == ruta_archivo:
                        # Registrar evento de modificación
                        self.registro_actividad[pid].append(ahora)
                        self.evaluar_patron_sospechoso(proc, pid)
                        break

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    def evaluar_patron_sospechoso(self, proc, pid):
        """Aplica las reglas heurísticas para detectar comportamiento anómalo."""
        ahora = time.time()
        # Filtrar solo modificaciones dentro de la ventana de tiempo definida
        self.registro_actividad[pid] = [
            t for t in self.registro_actividad[pid] if ahora - t <= VENTANA_TIEMPO
        ]

        # REGLA 1: Tasa de modificación recurrente acelerada (Anomalía de E/S)
        modificaciones_recientes = len(self.registro_actividad[pid])

        if modificaciones_recientes >= UMBRAL_MODIFICACIONES:
            print(f"\n🚨 [ANOMALÍA DETECTADA] Proceso PID {pid} superó el umbral de modificaciones.")
            print(f"📊 Patrón: {modificaciones_recientes} operaciones de archivo en {VENTANA_TIEMPO}s.")
            self.mitigar_y_aislar(proc)

    def mitigar_y_aislar(self, proc):
        """Acción autónoma: Detención inmediata y aislamiento del binario."""
        try:
            pid = proc.info['pid']
            nombre = proc.info['name']
            ruta_exe = proc.info['exe']

            self.procesos_mitigados.add(pid)

            # 1. Finalizar proceso de inmediato (Kill forzado en kernel)
            proc.kill()
            print(f"⚡ [AUTÓNOMO] Proceso {nombre} (PID: {pid}) detenido exitosamente.")

            # 2. Aislamiento en cuarentena
            if ruta_exe and os.path.exists(ruta_exe):
                nombre_binario = os.path.basename(ruta_exe)
                destino = os.path.join(DIR_CUARENTENA, f"{nombre_binario}.quarantine")
                
                # Desplazar ejecutable a la zona segura
                shutil.move(ruta_exe, destino)
                print(f"🔒 [CUARENTENA] Binario aislado en: {destino}")

        except Exception as e:
            print(f"❌ Error durante la mitigación autónoma: {e}")


def iniciar_sistema_deteccion():
    print("=" * 65)
    print(" 🛡️  SISTEMA DE DETECCIÓN Y MITIGACIÓN AUTÓNOMA HEURÍSTICA".center(65))
    print("=" * 65)
    print(f" [*] Modo: Análisis de comportamiento en tiempo real (Zero-Knowledge)")
    print(f" [*] Monitoreando ruta: {RUTA_MONITOREO}")
    print(f" [*] Regla activa: >{UMBRAL_MODIFICACIONES} modificaciones en {VENTANA_TIEMPO}s")
    print(" [*] Estado: Operando de forma autónoma sin intervención manual...\n")

    event_handler = MonitorComportamiento()
    observer = Observer()
    observer.schedule(event_handler, path=RUTA_MONITOREO, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n [!] Sistema de detección detenido.")
    observer.join()


if __name__ == "__main__":
    iniciar_sistema_deteccion()