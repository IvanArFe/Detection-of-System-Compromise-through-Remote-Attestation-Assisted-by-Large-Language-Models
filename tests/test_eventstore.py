"""Tests del almacén de eventos.

El test importante es el de concurrencia: reproduce exactamente el escenario que
corrompía los datos antes — el hilo del sensor escribiendo mientras el hilo de las
herramientas MCP lee.
"""

import json
import threading

from edr.eventstore import EventStore


def test_seq_es_monotonico_y_empieza_en_1(tmp_path):
    store = EventStore(tmp_path / "e.jsonl")

    assert store.append("execve", pid=1) == 1
    assert store.append("execve", pid=2) == 2
    assert store.append("module_load", pid=3) == 3


def test_los_eventos_llevan_timestamp_utc_ordenable(tmp_path):
    store = EventStore(tmp_path / "e.jsonl")
    store.append("execve", pid=1)
    store.append("execve", pid=2)

    eventos = store.query()
    # ISO-8601 en UTC: ordenable lexicográficamente y correlacionable con Supabase.
    assert eventos[0]["ts"] <= eventos[1]["ts"]
    assert "+00:00" in eventos[0]["ts"]


# ── concurrencia: el bug que motivó este módulo ────────────────

def test_escrituras_y_lecturas_concurrentes(tmp_path):
    """20 hilos escribiendo mientras otros leen: ni una excepción, ni un seq repetido.

    Antes, el hilo del sensor reescribía el fichero JSON entero mientras el hilo
    principal lo parseaba, produciendo JSONDecodeError intermitentes que llegaban
    al LLM como texto de error.
    """
    store = EventStore(tmp_path / "e.jsonl", cap=20000)
    errores = []
    seqs = []
    seqs_lock = threading.Lock()

    def escritor(n):
        try:
            propios = [store.append("execve", pid=n, i=i) for i in range(500)]
            with seqs_lock:
                seqs.extend(propios)
        except Exception as e:  # noqa: BLE001 — el test existe para detectar cualquier fallo
            errores.append(e)

    def lector():
        try:
            for _ in range(200):
                store.query(kind="execve", limit=50)
                store.pending(limit=50)
                store.stats()
        except Exception as e:  # noqa: BLE001
            errores.append(e)

    hilos = ([threading.Thread(target=escritor, args=(n,)) for n in range(20)]
             + [threading.Thread(target=lector) for _ in range(5)])
    for h in hilos:
        h.start()
    for h in hilos:
        h.join()

    assert errores == []
    assert len(seqs) == 10000
    assert len(set(seqs)) == 10000, "hay números de secuencia duplicados"


def test_el_jsonl_es_parseable_linea_a_linea(tmp_path):
    """Cada línea es independiente: una corrupta no invalida el fichero entero."""
    path = tmp_path / "e.jsonl"
    store = EventStore(path, cap=100)

    hilos = [threading.Thread(target=lambda n=n: [store.append("execve", pid=n, i=i)
                                                  for i in range(50)])
             for n in range(10)]
    for h in hilos:
        h.start()
    for h in hilos:
        h.join()

    lineas = path.read_text().strip().split("\n")
    assert len(lineas) == 500
    seqs = {json.loads(linea)["seq"] for linea in lineas}
    assert len(seqs) == 500


# ── capacidad ──────────────────────────────────────────────────

def test_la_memoria_esta_acotada_y_las_perdidas_se_cuentan(tmp_path):
    store = EventStore(tmp_path / "e.jsonl", cap=10)
    for i in range(25):
        store.append("execve", pid=i)

    stats = store.stats()
    assert stats["in_memory"] == 10
    # Descartar en silencio convertiría una pérdida de telemetría en algo invisible.
    assert stats["dropped"] == 15
    # Se conservan los más recientes.
    assert [e["pid"] for e in store.query(limit=100)] == list(range(15, 25))


def test_el_jsonl_conserva_el_historico_completo(tmp_path):
    """La memoria está acotada; el registro forense en disco, no."""
    path = tmp_path / "e.jsonl"
    store = EventStore(path, cap=5)
    for i in range(30):
        store.append("execve", pid=i)

    assert len(path.read_text().strip().split("\n")) == 30


# ── filtros ────────────────────────────────────────────────────

def test_filtra_por_kind_y_por_pid(tmp_path):
    store = EventStore(tmp_path / "e.jsonl")
    store.append("execve", pid=100)
    store.append("execve", pid=200)
    store.append("module_load", pid=100)

    assert len(store.query(kind="execve")) == 2
    assert len(store.query(pid=100)) == 2
    assert len(store.query(kind="module_load", pid=100)) == 1
    assert store.query(pid=999) == []


def test_since_seq_solo_devuelve_lo_nuevo(tmp_path):
    store = EventStore(tmp_path / "e.jsonl")
    for i in range(5):
        store.append("execve", pid=i)

    assert [e["pid"] for e in store.query(since_seq=3)] == [3, 4]


def test_query_devuelve_los_mas_recientes_al_desbordar(tmp_path):
    store = EventStore(tmp_path / "e.jsonl")
    for i in range(10):
        store.append("execve", pid=i)

    assert [e["pid"] for e in store.query(limit=3)] == [7, 8, 9]


# ── confirmación de eventos ────────────────────────────────────

def test_ack_evita_que_las_alertas_se_reanalicen_para_siempre(tmp_path):
    """El bug original: kernel_events.json no se vaciaba ni se marcaba nunca."""
    store = EventStore(tmp_path / "e.jsonl")
    for i in range(5):
        store.append("module_load", pid=i)

    pendientes = store.pending("module_load")
    assert len(pendientes) == 5

    store.ack(max(e["seq"] for e in pendientes))
    assert store.pending("module_load") == []

    store.append("module_load", pid=99)
    assert [e["pid"] for e in store.pending("module_load")] == [99]


def test_pending_devuelve_los_mas_antiguos_primero(tmp_path):
    """Al revés que query: la confirmación debe avanzar sin dejar huecos."""
    store = EventStore(tmp_path / "e.jsonl")
    for i in range(10):
        store.append("module_load", pid=i)

    assert [e["pid"] for e in store.pending(limit=3)] == [0, 1, 2]


def test_el_predicado_se_aplica_antes_del_recorte(tmp_path):
    """Regresión: filtrar después del `limit` habría hecho inútil el disparador.

    `pending` devuelve los MÁS ANTIGUOS, y la proporción real es de miles de
    eventos irrelevantes por cada uno que interesa. Recortando primero, la ventana
    se llenaría de ruido y el evento marcado —que es el último— quedaría fuera:
    el sistema no escalaría nunca nada.
    """
    store = EventStore(tmp_path / "e.jsonl")
    for i in range(100):
        store.append("execve", pid=i, interesante=(i == 99))

    pendientes = store.pending(limit=5, predicate=lambda e: e["interesante"])

    assert [e["pid"] for e in pendientes] == [99]


def test_sin_predicado_se_comporta_como_siempre(tmp_path):
    store = EventStore(tmp_path / "e.jsonl")
    for i in range(5):
        store.append("module_load", pid=i)

    assert len(store.pending(limit=5)) == 5


def test_el_predicado_convive_con_el_filtro_por_tipo(tmp_path):
    store = EventStore(tmp_path / "e.jsonl")
    store.append("module_load", pid=1, malo=True)
    store.append("execve", pid=2, malo=True)
    store.append("execve", pid=3, malo=False)

    pendientes = store.pending("execve", predicate=lambda e: e["malo"])

    assert [e["pid"] for e in pendientes] == [2]


def test_ack_es_monotono(tmp_path):
    """Un ack tardío o reintentado no puede hacer retroceder el puntero."""
    store = EventStore(tmp_path / "e.jsonl")
    for i in range(5):
        store.append("module_load", pid=i)

    assert store.ack(5) == 5
    assert store.ack(2) == 0
    assert store.pending("module_load") == []


def test_ack_parcial(tmp_path):
    store = EventStore(tmp_path / "e.jsonl")
    for i in range(5):
        store.append("module_load", pid=i)

    assert store.ack(3) == 3
    assert [e["pid"] for e in store.pending("module_load")] == [3, 4]


def test_ack_solo_afecta_a_pending_no_a_query(tmp_path):
    """La evidencia forense sigue consultable después de confirmarla."""
    store = EventStore(tmp_path / "e.jsonl")
    store.append("module_load", pid=1)
    store.ack(1)

    assert store.pending("module_load") == []
    assert len(store.query(kind="module_load")) == 1


# ── degradación ────────────────────────────────────────────────

def test_funciona_sin_fichero(tmp_path):
    """Modo solo-memoria: útil en tests y si el disco no está disponible."""
    store = EventStore(None)
    assert store.append("execve", pid=1) == 1
    assert len(store.query()) == 1


def test_un_disco_que_falla_no_detiene_la_deteccion(tmp_path, monkeypatch):
    """Detectar sin dejar rastro es malo; dejar de detectar es peor."""
    store = EventStore(tmp_path / "no" / "existe" / "e.jsonl")

    assert store.append("execve", pid=1) == 1
    assert len(store.query()) == 1
    assert store.stats()["jsonl"] is None
