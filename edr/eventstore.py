"""Almacén de eventos compartido entre los sensores y las herramientas MCP.

**El problema que resuelve.** Los sensores eBPF y el servidor MCP viven en el
mismo proceso pero en hilos distintos, y hasta ahora se comunicaban a través de
un fichero JSON: el hilo sensor lo reescribía entero en cada evento mientras el
hilo principal hacía `json.load` desde las herramientas. Sin sincronización. El
resultado eran `JSONDecodeError` intermitentes que acababan llegando al LLM como
texto de error y contaminaban su razonamiento con algo que interpretaba como
telemetría.

La solución no es poner un lock al fichero: es **sacar el fichero del camino de
datos**. Los eventos viven en memoria bajo un lock, y el fichero pasa a ser solo
registro forense append-only.

Tres propiedades, cada una matando un fallo de raíz:

- **Todo bajo `self._lock`**, y las herramientas leen de memoria, nunca del disco.
- **JSONL en vez de JSON reescrito.** Una línea corrupta no invalida el resto del
  fichero, y escribir una línea corta es efectivamente atómico.
- **`seq` monotónico y `ack` explícito.** Antes los eventos no se consumían nunca:
  pasada la ventana de deduplicación, la misma alerta se reanalizaba eternamente.
  Ahora el orquestador confirma lo que ya procesó, de forma auditable.
"""

import json
import threading
from collections import deque
from datetime import datetime, timezone


def utc_now():
    """Marca de tiempo ISO-8601 en UTC.

    El formato anterior (`%d-%m-%Y %H:%M:%S` en hora local) no llevaba zona ni
    subsegundos y no era ordenable lexicográficamente, así que no se podía
    correlacionar con los TIMESTAMPTZ que Supabase guarda en UTC. Hará falta para
    medir latencias de detección.
    """
    return datetime.now(timezone.utc).isoformat()


class EventStore:
    """Cola de eventos acotada, segura entre hilos, con confirmación explícita."""

    def __init__(self, jsonl_path=None, cap=2000):
        self._lock = threading.Lock()
        self._events = deque(maxlen=cap)
        self._next_seq = 1
        self._acked = 0
        self._dropped = 0
        self._jsonl_path = str(jsonl_path) if jsonl_path else None
        self._fh = None

    # ── escritura ──────────────────────────────────────────────

    def append(self, kind, **fields):
        """Registra un evento y devuelve su número de secuencia.

        El evento se guarda en memoria ANTES de intentar escribirlo a disco: si el
        disco falla (lleno, solo lectura), se pierde el registro forense pero no la
        detección. Un sensor que deja de detectar porque no puede escribir un log
        es peor que uno que detecta sin dejar rastro.
        """
        with self._lock:
            event = {"seq": self._next_seq, "ts": utc_now(), "kind": kind}
            event.update(fields)
            self._next_seq += 1

            # deque con maxlen descarta por la izquierda en silencio: contarlo es
            # lo que convierte una pérdida invisible en una métrica.
            if len(self._events) == self._events.maxlen:
                self._dropped += 1
            self._events.append(event)

            self._write_line(event)
            return event["seq"]

    def _write_line(self, event):
        """Añade una línea al JSONL. Se llama con el lock ya tomado."""
        if not self._jsonl_path:
            return
        try:
            if self._fh is None:
                self._fh = open(self._jsonl_path, "a", encoding="utf-8")
            self._fh.write(json.dumps(event, ensure_ascii=False) + "\n")
            self._fh.flush()
        except OSError:
            # Se degrada a solo-memoria en vez de propagar hacia el hilo sensor.
            self._jsonl_path = None
            self._fh = None

    # ── lectura ────────────────────────────────────────────────

    def query(self, kind=None, pid=None, since_seq=0, limit=50):
        """Eventos que casan con los filtros, en orden cronológico.

        Cuando hay más coincidencias que `limit` se devuelven las MÁS RECIENTES:
        ante un desbordamiento, lo último que pasó es más informativo que lo
        primero.
        """
        with self._lock:
            matches = [
                e for e in self._events
                if e["seq"] > since_seq
                and (kind is None or e["kind"] == kind)
                and (pid is None or e.get("pid") == pid)
            ]
        return matches[-limit:] if limit and limit > 0 else matches

    def pending(self, kind=None, limit=50, predicate=None):
        """Eventos aún no confirmados, del más antiguo al más reciente.

        Aquí el orden importa al revés que en `query`: se devuelven los más
        ANTIGUOS para que la confirmación avance de forma contigua y no queden
        huecos sin procesar entre medias.

        `predicate` es un invocable que decide si un evento cuenta, y se aplica
        **antes** del recorte por `limit`. El orden no es un detalle: como se
        devuelven los más antiguos, con miles de eventos irrelevantes por delante
        —que es exactamente la proporción real de los execve— filtrar después del
        recorte devolvería una ventana llena de ruido y dejaría fuera justo los
        eventos que interesan.

        El almacén no sabe nada de en qué consiste ser interesante: recibe la
        decisión ya tomada desde fuera.
        """
        with self._lock:
            matches = [
                e for e in self._events
                if e["seq"] > self._acked
                and (kind is None or e["kind"] == kind)
                and (predicate is None or predicate(e))
            ]
        return matches[:limit] if limit and limit > 0 else matches

    # ── confirmación ───────────────────────────────────────────

    def ack(self, up_to_seq):
        """Marca como consumido todo evento con `seq <= up_to_seq`.

        Es monótona: una confirmación con un `seq` menor que el actual se ignora.
        Sin esa garantía, una respuesta tardía o un reintento del orquestador
        podría hacer retroceder el puntero y provocar que se reanalizaran alertas
        ya resueltas.
        """
        with self._lock:
            up_to_seq = int(up_to_seq)
            if up_to_seq <= self._acked:
                return 0
            newly = sum(
                1 for e in self._events if self._acked < e["seq"] <= up_to_seq
            )
            self._acked = up_to_seq
            return newly

    # ── introspección ──────────────────────────────────────────

    def stats(self):
        """Contadores para diagnóstico y para el capítulo de rendimiento."""
        with self._lock:
            return {
                "in_memory": len(self._events),
                "next_seq": self._next_seq,
                "acked": self._acked,
                "dropped": self._dropped,
                "jsonl": self._jsonl_path,
            }

    def close(self):
        with self._lock:
            if self._fh is not None:
                try:
                    self._fh.close()
                except OSError:
                    pass
                self._fh = None
