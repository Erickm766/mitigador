"""
=============================================================================
 Sistema de Detección Autónoma de Ransomware — por comportamiento
=============================================================================
Proyecto Final - Seguridad de TI I

Este programa es puramente DEFENSIVO: no cifra, no daña ni modifica nada.
Su único propósito es observar el sistema de archivos y los procesos en
ejecución, calcular métricas de comportamiento, y reaccionar de forma
autónoma cuando detecta un patrón consistente con cifrado masivo no
autorizado (ransomware).

Principio de diseño (según la rúbrica del proyecto):
La detección se basa ÚNICAMENTE en rastros y comportamiento observable:
    1. Entropía de los archivos modificados (un archivo cifrado se ve
       estadísticamente como ruido aleatorio).
    2. Tasa de modificación de archivos por unidad de tiempo.
    3. Aparición masiva y repetida de una extensión nueva/desconocida.
    4. Actividad de E/S de disco anormalmente alta en un proceso.

No se hardcodea ninguna extensión específica de ransomware ni el nombre
de ningún proceso conocido — el detector debe funcionar contra CUALQUIER
ransomware que cifre archivos de esta forma, no solo contra uno en
particular.

Dependencias:
    pip install watchdog psutil
"""

import os
import sys
import time
import math
import shutil
import psutil
import logging
import threading
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ---------------------------------------------------------------------------
# CONFIGURACIÓN
# ---------------------------------------------------------------------------

# Raíz a vigilar. Todo el disco local C:\ según lo solicitado.
RUTA_VIGILADA = "C:\\"

# Carpetas de sistema a excluir (no aportan señal útil y generan ruido/carga)
CARPETAS_EXCLUIDAS = {
    "windows", "system32", "program files", "program files (x86)",
    "$recycle.bin", "programdata", "appdata", "$windows.~ws",
    "system volume information", "recovery",
}

# Carpeta de cuarentena donde se aíslan los ejecutables sospechosos
CARPETA_CUARENTENA = Path("C:\\Cuarentena_Detector")

# --- Umbrales de comportamiento (ajustables tras pruebas en tu VM) ---

# Nº de eventos de archivo (crear/modificar/renombrar) en la ventana de tiempo
# que se considera una ráfaga sospechosa.
UMBRAL_EVENTOS_POR_VENTANA = 8
VENTANA_SEGUNDOS = 5  # coincide con el ciclo de 5s mencionado en el proyecto

# Entropía de Shannon (0-8 bits/byte). Por encima de este valor, el
# contenido es estadísticamente indistinguible de datos cifrados/comprimidos.
UMBRAL_ENTROPIA = 7.5

# Nº mínimo de extensiones "nuevas" repetidas para sospechar un patrón
# de renombrado masivo (no se compara contra una lista fija de extensiones
# maliciosas conocidas — se detecta la REPETICIÓN anómala en sí misma).
UMBRAL_EXTENSIONES_REPETIDAS = 5

# Bytes escritos por segundo que se consideran actividad de disco anómala
# para un proceso de usuario normal.
UMBRAL_ESCRITURA_BYTES_SEG = 5 * 1024 * 1024  # 5 MB/s sostenidos

# Puntaje combinado necesario para disparar la respuesta autónoma.
# Ninguna señal aislada basta — se exige correlación, para evitar falsos
# positivos (ej. alguien copiando una carpeta de fotos manualmente).
PUNTAJE_ACCION = 6

# Procesos propios del sistema que nunca deben evaluarse ni terminarse
PROCESOS_PROTEGIDOS = {
    "system", "system idle process", "svchost.exe", "explorer.exe",
    "wininit.exe", "csrss.exe", "smss.exe", "services.exe",
    "lsass.exe", "python.exe",  # excluye el propio detector si corre en python.exe
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("detector")


# ---------------------------------------------------------------------------
# UTILIDADES
# ---------------------------------------------------------------------------

def ruta_excluida(ruta: str) -> bool:
    partes = Path(ruta).parts
    partes_lower = {p.lower() for p in partes}
    return any(excl in partes_lower for excl in CARPETAS_EXCLUIDAS) or \
        str(CARPETA_CUARENTENA) in ruta


def calcular_entropia(ruta_archivo: str, muestra_bytes: int = 65536) -> float:
    """
    Calcula la entropía de Shannon de una muestra del archivo.
    Valores cercanos a 8.0 = contenido con apariencia de aleatoriedad total
    (típico de datos cifrados). Valores bajos = texto, código, XML, etc.
    """
    try:
        with open(ruta_archivo, "rb") as f:
            datos = f.read(muestra_bytes)
    except (PermissionError, FileNotFoundError, OSError):
        return 0.0

    if not datos:
        return 0.0

    frecuencias = defaultdict(int)
    for byte in datos:
        frecuencias[byte] += 1

    entropia = 0.0
    longitud = len(datos)
    for cuenta in frecuencias.values():
        p = cuenta / longitud
        entropia -= p * math.log2(p)

    return entropia


# ---------------------------------------------------------------------------
# SEGUIMIENTO DE COMPORTAMIENTO (ventana deslizante)
# ---------------------------------------------------------------------------

class RastreadorComportamiento:
    """
    Mantiene, por carpeta raíz vigilada, un historial reciente de eventos
    para poder calcular tasas y patrones dentro de una ventana de tiempo.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.eventos = deque()  # (timestamp, ruta, extension)
        self.extensiones_recientes = defaultdict(int)

    def registrar_evento(self, ruta: str):
        ahora = time.time()
        ext = Path(ruta).suffix.lower()
        with self.lock:
            self.eventos.append((ahora, ruta, ext))
            self.extensiones_recientes[ext] += 1
            self._purgar(ahora)

    def _purgar(self, ahora: float):
        while self.eventos and ahora - self.eventos[0][0] > VENTANA_SEGUNDOS:
            _, _, ext_vieja = self.eventos.popleft()
            self.extensiones_recientes[ext_vieja] -= 1
            if self.extensiones_recientes[ext_vieja] <= 0:
                del self.extensiones_recientes[ext_vieja]

    def snapshot(self):
        with self.lock:
            ahora = time.time()
            self._purgar(ahora)
            return list(self.eventos), dict(self.extensiones_recientes)


rastreador = RastreadorComportamiento()


# ---------------------------------------------------------------------------
# MANEJADOR DE EVENTOS DE SISTEMA DE ARCHIVOS
# ---------------------------------------------------------------------------

class ManejadorArchivos(FileSystemEventHandler):

    def on_created(self, event):
        self._procesar(event)

    def on_modified(self, event):
        self._procesar(event)

    def on_moved(self, event):
        # Cubre el patrón: leer original -> escribir cifrado -> renombrar
        self._procesar(event, ruta=getattr(event, "dest_path", event.src_path))

    def _procesar(self, event, ruta=None):
        if event.is_directory:
            return
        ruta = ruta or event.src_path
        if ruta_excluida(ruta):
            return
        rastreador.registrar_evento(ruta)


# ---------------------------------------------------------------------------
# EVALUADOR DE PROCESOS (atribución + respuesta)
# ---------------------------------------------------------------------------

class EvaluadorProcesos:
    """
    Calcula tasas de escritura a disco por proceso, para poder atribuir
    una ráfaga sospechosa de eventos de archivo al proceso responsable.
    """

    def __init__(self):
        self._io_anterior = {}

    def procesos_con_escritura_alta(self):
        sospechosos = []
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                nombre = (proc.info["name"] or "").lower()
                if nombre in PROCESOS_PROTEGIDOS:
                    continue

                io = proc.io_counters()
                pid = proc.info["pid"]
                ahora = time.time()

                anterior = self._io_anterior.get(pid)
                self._io_anterior[pid] = (io.write_bytes, ahora)

                if anterior is None:
                    continue

                bytes_prev, t_prev = anterior
                delta_t = max(ahora - t_prev, 0.001)
                tasa = (io.write_bytes - bytes_prev) / delta_t

                if tasa >= UMBRAL_ESCRITURA_BYTES_SEG:
                    sospechosos.append((proc, tasa))

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return sorted(sospechosos, key=lambda x: x[1], reverse=True)


evaluador = EvaluadorProcesos()


# ---------------------------------------------------------------------------
# RESPUESTA AUTÓNOMA
# ---------------------------------------------------------------------------

def contener_amenaza(proc: psutil.Process):
    try:
        exe_path = proc.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        exe_path = None

    nombre = proc.name()
    pid = proc.pid

    log.warning(f"CONTENIENDO PROCESO SOSPECHOSO -> {nombre} (PID {pid})")

    try:
        proc.terminate()
        proc.wait(timeout=3)
    except psutil.TimeoutExpired:
        proc.kill()
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        log.error(f"No se pudo terminar el proceso {pid}: {e}")
        return

    log.info(f"Proceso {nombre} (PID {pid}) terminado.")

    if exe_path and os.path.exists(exe_path):
        try:
            CARPETA_CUARENTENA.mkdir(parents=True, exist_ok=True)
            destino = CARPETA_CUARENTENA / f"{Path(exe_path).name}.quarantine"
            shutil.move(exe_path, destino)
            log.info(f"Ejecutable aislado en cuarentena: {destino}")
        except (OSError, PermissionError) as e:
            log.error(f"No se pudo mover a cuarentena: {e}")


# ---------------------------------------------------------------------------
# BUCLE PRINCIPAL DE ANÁLISIS (autónomo, continuo)
# ---------------------------------------------------------------------------

def ciclo_analisis():
    log.info("Motor de análisis de comportamiento iniciado.")

    while True:
        time.sleep(1)  # el detector debe escanear MÁS rápido que el ciclo
                        # de 5s del ransomware, según lo pide el proyecto

        eventos, extensiones = rastreador.snapshot()
        puntaje = 0
        detalles = []

        # Señal 1: tasa de eventos en la ventana
        if len(eventos) >= UMBRAL_EVENTOS_POR_VENTANA:
            puntaje += 2
            detalles.append(f"{len(eventos)} eventos de archivo en {VENTANA_SEGUNDOS}s")

        # Señal 2: extensión repetida de forma anómala (patrón de renombrado masivo)
        for ext, cuenta in extensiones.items():
            if ext and cuenta >= UMBRAL_EXTENSIONES_REPETIDAS:
                puntaje += 2
                detalles.append(f"extensión '{ext}' repetida {cuenta} veces")
                break

        # Señal 3: entropía alta en una muestra de los archivos recién tocados
        if eventos:
            muestra = eventos[-5:]  # últimos 5 eventos, para no saturar E/S
            entropias_altas = 0
            for _, ruta, _ in muestra:
                if os.path.exists(ruta) and calcular_entropia(ruta) >= UMBRAL_ENTROPIA:
                    entropias_altas += 1
            if entropias_altas >= 2:
                puntaje += 3
                detalles.append(f"{entropias_altas} archivos con entropía >= {UMBRAL_ENTROPIA}")

        if puntaje == 0:
            continue

        # Señal 4: correlación con proceso de escritura alta a disco
        sospechosos = evaluador.procesos_con_escritura_alta()
        if sospechosos:
            puntaje += 2
            proc_top, tasa = sospechosos[0]
            detalles.append(
                f"proceso '{proc_top.name()}' (PID {proc_top.pid}) "
                f"escribiendo {tasa/1024/1024:.1f} MB/s"
            )

        log.info(f"Puntaje de riesgo actual: {puntaje} | " + "; ".join(detalles))

        if puntaje >= PUNTAJE_ACCION and sospechosos:
            log.warning("PATRÓN DE RANSOMWARE DETECTADO. Iniciando contención autónoma.")
            proc_objetivo, _ = sospechosos[0]
            contener_amenaza(proc_objetivo)

            # Limpiar estado tras actuar, para no re-disparar sobre el mismo evento
            rastreador.eventos.clear()
            rastreador.extensiones_recientes.clear()


# ---------------------------------------------------------------------------
# ARRANQUE
# ---------------------------------------------------------------------------

def main():
    if not Path(RUTA_VIGILADA).exists():
        log.error(f"La ruta a vigilar no existe: {RUTA_VIGILADA}")
        sys.exit(1)

    log.info(f"Iniciando vigilancia autónoma sobre: {RUTA_VIGILADA}")
    log.info(f"Carpetas excluidas: {sorted(CARPETAS_EXCLUIDAS)}")

    manejador = ManejadorArchivos()
    observer = Observer()
    observer.schedule(manejador, RUTA_VIGILADA, recursive=True)
    observer.start()

    hilo_analisis = threading.Thread(target=ciclo_analisis, daemon=True)
    hilo_analisis.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Deteniendo detector...")
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()