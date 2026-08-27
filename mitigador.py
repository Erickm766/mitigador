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

# Formatos cuyo contenido YA es naturalmente de alta entropía (comprimidos,
# multimedia, etc.). Un archivo de estos tipos con entropía alta es NORMAL,
# no una señal de cifrado — se excluyen del chequeo rápido por evento
# individual para no generar falsos positivos.
EXTENSIONES_ALTA_ENTROPIA_NATURAL = {
    ".zip", ".rar", ".7z", ".gz", ".tar", ".xz", ".bz2",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp4", ".mp3",
    ".mov", ".avi", ".mkv",
}

# Procesos propios del sistema que nunca deben evaluarse ni terminarse.
# IMPORTANTE: NO se excluye "python.exe" por nombre, porque el ransomware
# probablemente también corre sobre el intérprete de Python y tendría el
# mismo nombre de proceso que el detector — excluirlo por nombre lo
# invisibilizaría por completo. En su lugar, el propio detector se protege
# a sí mismo por PID (ver PID_PROPIO más abajo), no por nombre genérico.
PROCESOS_PROTEGIDOS = {
    "system", "system idle process", "svchost.exe", "explorer.exe",
    "wininit.exe", "csrss.exe", "smss.exe", "services.exe", "lsass.exe",
    # Procesos legítimos de Windows que generan picos de E/S como REACCIÓN
    # a cambios masivos de archivos (no como causa) y por eso pueden dar
    # falsos positivos si solo se mide volumen de escritura a disco.
    "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "msmpeng.exe", "nissrv.exe",  # Windows Defender
    "trustedinstaller.exe", "tiworker.exe",
    "backgroundtaskhost.exe", "dllhost.exe",
    "onedrive.exe", "wmiprvse.exe",
}

# Nombres de intérprete que indican que el "proceso" real a aislar no es el
# .exe en sí, sino el script que recibe como argumento (python archivo.py).
# Esto permite que la contención funcione igual de bien tanto si el
# ransomware corre como script interpretado (cualquier nombre de archivo)
# como si corre ya compilado en un .exe independiente.
INTERPRETES_SCRIPT = {"python.exe", "pythonw.exe", "py.exe"}

# PID del propio proceso del detector, para excluirse a sí mismo sin
# depender del nombre del intérprete (python.exe, pythonw.exe, etc.)
PID_PROPIO = os.getpid()

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

    También detecta PERIODICIDAD: si las ráfagas de actividad ocurren a
    intervalos regulares (sin importar cuál sea ese intervalo), es una
    señal de automatización -- un humano editando archivos lo hace de
    forma irregular; un bucle programado no.
    """

    # Silencio mínimo (segundos) para considerar que empezó una NUEVA ráfaga
    SILENCIO_ENTRE_RAFAGAS = 1.5
    # Cuántos intervalos entre ráfagas se necesitan para evaluar regularidad
    MIN_INTERVALOS_PARA_EVALUAR = 3
    # Máxima variación relativa (coeficiente de variación) para considerar
    # el patrón "sospechosamente regular". Cuanto más bajo, más estricto.
    UMBRAL_REGULARIDAD = 0.25
    # Rango de intervalo típico de un ciclo automatizado de cifrado
    # (evita falsos positivos con procesos de intervalo muy corto tipo
    # autoguardado, o muy largo tipo tareas programadas de respaldo)
    INTERVALO_MIN_SEG = 1.0
    INTERVALO_MAX_SEG = 30.0

    def __init__(self):
        self.lock = threading.Lock()
        self.eventos = deque()  # (timestamp, ruta, extension)
        self.extensiones_recientes = defaultdict(int)
        self._ultimo_evento_ts = 0.0
        self._inicios_de_rafaga = deque(maxlen=10)

    def registrar_evento(self, ruta: str):
        ahora = time.time()
        ext = Path(ruta).suffix.lower()
        with self.lock:
            # Detectar si este evento arranca una nueva ráfaga (hubo
            # silencio suficiente antes) para medir periodicidad.
            if ahora - self._ultimo_evento_ts >= self.SILENCIO_ENTRE_RAFAGAS:
                self._inicios_de_rafaga.append(ahora)
            self._ultimo_evento_ts = ahora

            self.eventos.append((ahora, ruta, ext))
            self.extensiones_recientes[ext] += 1
            self._purgar(ahora)

    def patron_periodico_detectado(self):
        """
        Devuelve (True, intervalo_promedio) si las ráfagas recientes
        ocurren a intervalos regulares dentro del rango típico de un
        ciclo automatizado. No asume ningún valor fijo de segundos.
        """
        with self.lock:
            inicios = list(self._inicios_de_rafaga)

        if len(inicios) < self.MIN_INTERVALOS_PARA_EVALUAR + 1:
            return False, 0.0

        intervalos = [b - a for a, b in zip(inicios, inicios[1:])]
        intervalos_en_rango = [
            i for i in intervalos
            if self.INTERVALO_MIN_SEG <= i <= self.INTERVALO_MAX_SEG
        ]
        if len(intervalos_en_rango) < self.MIN_INTERVALOS_PARA_EVALUAR:
            return False, 0.0

        promedio = sum(intervalos_en_rango) / len(intervalos_en_rango)
        varianza = sum((i - promedio) ** 2 for i in intervalos_en_rango) / len(intervalos_en_rango)
        desviacion = math.sqrt(varianza)
        coef_variacion = desviacion / promedio if promedio > 0 else 999

        return coef_variacion <= self.UMBRAL_REGULARIDAD, promedio

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

def es_evento_fuertemente_sospechoso(ruta: str) -> bool:
    """
    Chequeo RÁPIDO por evento individual (no depende de acumular ventana
    de tiempo, así que funciona igual de bien con archivos pequeños).

    Señal fuerte: un archivo cuya extensión normalmente indicaría contenido
    de baja/media entropía (texto, documentos, código, etc.) aparece con
    entropía muy alta — es decir, su contenido ya no se parece en nada a lo
    que su extensión promete. Eso es exactamente lo que ocurre cuando un
    archivo original se sobrescribe con su versión cifrada.

    Se excluyen deliberadamente formatos que YA son de alta entropía por
    naturaleza (zip, jpg, mp4, etc.) para no disparar con actividad normal.
    """
    ext = Path(ruta).suffix.lower()
    if ext in EXTENSIONES_ALTA_ENTROPIA_NATURAL:
        return False
    if not os.path.exists(ruta):
        return False
    return calcular_entropia(ruta) >= UMBRAL_ENTROPIA


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

        # Camino rápido: no esperar a que se acumule puntaje en la ventana
        # de 5s si UN SOLO archivo ya muestra una señal fuerte e inequívoca.
        # Relevante para tandas de archivos pequeños, donde el volumen de
        # E/S nunca sube lo suficiente para las otras señales.
        if es_evento_fuertemente_sospechoso(ruta):
            log.warning(f"Señal fuerte inmediata en archivo individual: {ruta}")
            reaccionar_evento_individual(ruta)


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

    def todos_ordenados_por_escritura(self):
        """
        Devuelve TODOS los procesos candidatos (no protegidos) ordenados por
        tasa de escritura a disco, de mayor a menor — sin filtrar por umbral.
        Se usa para poder identificar al responsable aunque su tasa de
        escritura no alcance UMBRAL_ESCRITURA_BYTES_SEG (por ejemplo, si el
        ransomware cifra archivos pequeños y nunca sostiene 5 MB/s).
        """
        candidatos = []
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                if pid == PID_PROPIO:
                    continue
                nombre = (proc.info["name"] or "").lower()
                if nombre in PROCESOS_PROTEGIDOS:
                    continue

                io = proc.io_counters()
                ahora = time.time()
                anterior = self._io_anterior.get(pid)
                self._io_anterior[pid] = (io.write_bytes, ahora)
                if anterior is None:
                    continue

                bytes_prev, t_prev = anterior
                delta_t = max(ahora - t_prev, 0.001)
                tasa = (io.write_bytes - bytes_prev) / delta_t
                if tasa > 0:
                    candidatos.append((proc, tasa))

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return sorted(candidatos, key=lambda x: x[1], reverse=True)

    def procesos_con_escritura_alta(self):
        return [
            (proc, tasa) for proc, tasa in self.todos_ordenados_por_escritura()
            if tasa >= UMBRAL_ESCRITURA_BYTES_SEG
        ]


evaluador = EvaluadorProcesos()


def identificar_por_archivos_abiertos(rutas_recientes: set):
    """
    Identificación PRIMARIA y más precisa del proceso responsable: revisa,
    entre todos los procesos activos, cuál tiene actualmente abierto (o
    tuvo abierto) alguno de los archivos que el vigilante de sistema de
    archivos marcó como parte de la ráfaga sospechosa.

    Esto es más confiable que medir solo "quién escribe más a disco",
    porque procesos legítimos del sistema (indexador de búsqueda,
    antivirus, sincronización de nube) también generan picos de E/S como
    REACCIÓN a los cambios masivos, sin ser la causa de ellos.
    """
    if not rutas_recientes:
        return None

    for proc in psutil.process_iter(["pid", "name"]):
        try:
            pid = proc.info["pid"]
            if pid == PID_PROPIO:
                continue
            nombre = (proc.info["name"] or "").lower()
            if nombre in PROCESOS_PROTEGIDOS:
                continue

            for archivo_abierto in proc.open_files():
                if archivo_abierto.path in rutas_recientes:
                    return proc

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return None


# ---------------------------------------------------------------------------
# RESPUESTA AUTÓNOMA
# ---------------------------------------------------------------------------

def resolver_objetivo_real(proc: psutil.Process):
    """
    Determina la ruta que realmente debe aislarse.

    Si el proceso es el intérprete de Python (python.exe, pythonw.exe, py.exe),
    NO se debe aislar el intérprete —eso rompería el sistema y probablemente
    falle por permisos—. En su lugar, se busca el script que se le pasó como
    argumento (cualquiera que sea su nombre) y esa es la ruta a aislar.

    Si el proceso ya es un ejecutable independiente (.exe compilado, ej. con
    PyInstaller), su propia ruta es el objetivo, como antes.
    """
    try:
        nombre = proc.name().lower()
        exe_path = proc.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None, "desconocido"

    if nombre not in INTERPRETES_SCRIPT:
        return exe_path, "ejecutable"

    # El proceso es el intérprete: buscar el script en los argumentos
    try:
        cmdline = proc.cmdline()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None, "desconocido"

    for arg in cmdline[1:]:
        # Cualquier argumento que apunte a un archivo .py existente,
        # sin importar el nombre que le haya puesto el atacante.
        if arg.lower().endswith(".py") and os.path.exists(arg):
            return os.path.abspath(arg), "script"

    # No se encontró un .py explícito (ej. -c "código inline"): no hay
    # archivo físico que aislar, solo se puede terminar el proceso.
    return None, "sin_archivo"


def contener_amenaza(proc: psutil.Process):
    nombre = proc.name()
    pid = proc.pid

    ruta_objetivo, tipo = resolver_objetivo_real(proc)

    log.warning(f"CONTENIENDO PROCESO SOSPECHOSO -> {nombre} (PID {pid}) [{tipo}]")

    try:
        proc.terminate()
        proc.wait(timeout=3)
    except psutil.TimeoutExpired:
        proc.kill()
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        log.error(f"No se pudo terminar el proceso {pid}: {e}")
        return

    log.info(f"Proceso {nombre} (PID {pid}) terminado.")

    if tipo == "sin_archivo":
        log.warning(
            "No se identificó un archivo .py físico para aislar "
            "(posible ejecución inline). Se terminó el proceso únicamente."
        )
        return

    if ruta_objetivo and os.path.exists(ruta_objetivo):
        try:
            CARPETA_CUARENTENA.mkdir(parents=True, exist_ok=True)
            destino = CARPETA_CUARENTENA / f"{Path(ruta_objetivo).name}.quarantine"
            shutil.move(ruta_objetivo, destino)
            log.info(f"Archivo aislado en cuarentena: {destino}")
        except (OSError, PermissionError) as e:
            log.error(f"No se pudo mover a cuarentena: {e}")


_ULTIMA_ACCION_INDIVIDUAL = 0.0
_LOCK_ACCION_INDIVIDUAL = threading.Lock()

def reaccionar_evento_individual(ruta: str):
    """
    Respuesta inmediata ante un solo archivo con señal fuerte, sin esperar
    a que se acumule el puntaje de la ventana de 5s. Pensado para el caso
    de archivos de prueba pequeños, donde el volumen de E/S nunca sube lo
    suficiente para disparar la señal de "escritura anómala".

    Incluye un pequeño "debounce": si ya se actuó hace menos de 2 segundos,
    no se vuelve a intentar de inmediato (evita duplicar acciones mientras
    el mismo proceso sigue cifrando el siguiente archivo del lote).
    """
    global _ULTIMA_ACCION_INDIVIDUAL
    with _LOCK_ACCION_INDIVIDUAL:
        ahora = time.time()
        if ahora - _ULTIMA_ACCION_INDIVIDUAL < 2.0:
            return
        _ULTIMA_ACCION_INDIVIDUAL = ahora

    proc_objetivo = identificar_por_archivos_abiertos({ruta})

    if not proc_objetivo:
        # Respaldo: proceso con mayor escritura a disco en este instante
        candidatos = evaluador.todos_ordenados_por_escritura()
        proc_objetivo = candidatos[0][0] if candidatos else None

    if not proc_objetivo:
        log.warning(
            "Señal fuerte detectada pero aún no se pudo identificar el "
            "proceso responsable en este ciclo (probará de nuevo con el "
            "siguiente evento o por el análisis de ventana)."
        )
        return

    log.warning("PATRÓN DE RANSOMWARE DETECTADO (evento individual). Conteniendo.")
    contener_amenaza(proc_objetivo)
    rastreador.eventos.clear()
    rastreador.extensiones_recientes.clear()


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

        # Señal 2b: periodicidad -- ráfagas de actividad a intervalos
        # regulares, sin importar cuál sea el intervalo exacto (no se
        # asume ningún valor fijo como "cada 5 segundos").
        es_periodico, intervalo_prom = rastreador.patron_periodico_detectado()
        if es_periodico:
            puntaje += 2
            detalles.append(f"ráfagas periódicas cada ~{intervalo_prom:.1f}s")

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
        # (esta lista SOLO alimenta puntaje; ver abajo la identificación
        # real del responsable, que no depende de este umbral)
        sospechosos = evaluador.procesos_con_escritura_alta()
        if sospechosos:
            puntaje += 2
            proc_top, tasa = sospechosos[0]
            detalles.append(
                f"proceso '{proc_top.name()}' (PID {proc_top.pid}) "
                f"escribiendo {tasa/1024/1024:.2f} MB/s"
            )

        log.info(f"Puntaje de riesgo actual: {puntaje} | " + "; ".join(detalles))

        if puntaje == 0:
            continue

        if puntaje >= PUNTAJE_ACCION:
            # 1) Identificación PRIMARIA: qué proceso tiene abiertos los
            #    archivos específicos que se marcaron como sospechosos.
            #    Esto es mucho más preciso que solo medir volumen de E/S.
            rutas_recientes = {ruta for _, ruta, _ in eventos}
            proc_objetivo = identificar_por_archivos_abiertos(rutas_recientes)

            if proc_objetivo:
                log.info(
                    f"Responsable identificado por archivo abierto: "
                    f"{proc_objetivo.name()} (PID {proc_objetivo.pid})"
                )
            else:
                # 2) Respaldo: si no se logró correlacionar por archivo
                #    (ej. el proceso ya cerró el handle tras escribir),
                #    se recurre al proceso con mayor escritura a disco,
                #    excluyendo siempre los procesos legítimos conocidos.
                candidatos = evaluador.todos_ordenados_por_escritura()
                if candidatos:
                    top3 = ", ".join(
                        f"{p.name()}(PID {p.pid}): {t/1024:.1f} KB/s"
                        for p, t in candidatos[:3]
                    )
                    log.info(f"Sin match por archivo. Candidatos por E/S -> {top3}")
                    proc_objetivo, _ = candidatos[0]
                else:
                    log.warning(
                        "Puntaje suficiente pero no se identificó ningún "
                        "proceso responsable (ni por archivo abierto ni por "
                        "E/S). Verifica que el detector corre como "
                        "Administrador."
                    )
                    continue

            log.warning("PATRÓN DE RANSOMWARE DETECTADO. Iniciando contención autónoma.")
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