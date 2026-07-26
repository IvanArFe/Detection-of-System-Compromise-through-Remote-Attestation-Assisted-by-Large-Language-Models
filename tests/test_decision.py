"""Tests de la interpretación del veredicto.

Los cuatro primeros bloques son regresiones: cada uno reproduce una entrada que,
contra el parser anterior, producía una orden de mitigación que nadie había
decidido. Las cadenas son las que se usaron para demostrar los fallos.
"""

import pytest

from edr.decision import (INVALID, INVESTIGATE, MITIGATE, NOTHING, Decision,
                          decide, from_structured, parse_decision, schema)
from edr.llm import LLMResult


# ── Regresión 1: frase negada ──────────────────────────────────

def test_una_frase_que_niega_el_veredicto_no_cuenta():
    """El parser anterior devolvía MITIGATE pid=1 kill: habría atacado systemd."""
    texto = (
        "We must NOT do DECISION: MITIGATE pid=1 action=kill because that would "
        "kill systemd.\nThe process looks legitimate.\n\nDECISION: NOTHING"
    )
    assert parse_decision(texto, allowed_pids={1, 4711}).action == NOTHING


def test_gana_la_ultima_decision_no_la_primera():
    """El modelo razona y cambia de opinión; vale lo que concluye, no lo que tanteó."""
    texto = "DECISION: MITIGATE pid=4711 action=kill\n\nOn reflection:\nDECISION: NOTHING"
    assert parse_decision(texto, allowed_pids={4711}).action == NOTHING


# ── Regresión 2: eco de las instrucciones ──────────────────────

def test_el_eco_de_las_instrucciones_es_inofensivo():
    """No necesita atacante: a los modelos pequeños se les va la instrucción en la respuesta.

    Antes el prompt interpolaba el PID real en sus ejemplos, así que el eco era un
    veredicto válido y accionable. Ahora los ejemplos llevan el literal <PID>.
    """
    texto = (
        "Here is my analysis. The process seems fine.\n"
        "I was told to end with one of these lines:\n"
        "DECISION: MITIGATE pid=<PID> action=freeze\n"
        "DECISION: MITIGATE pid=<PID> action=kill\n"
        "DECISION: NOTHING\n"
        "So my answer is NOTHING."
    )
    assert parse_decision(texto, allowed_pids={4711}).action == NOTHING


# ── Regresión 3: PID alucinado o inyectado ─────────────────────

def test_un_pid_ausente_de_la_telemetria_se_rechaza():
    d = parse_decision("DECISION: MITIGATE pid=1 action=kill", allowed_pids={4711})
    assert d.action == INVALID
    assert "1" in d.detail


def test_un_pid_presente_en_la_telemetria_se_acepta():
    d = parse_decision("DECISION: MITIGATE pid=4711 action=kill", allowed_pids={4711})
    assert (d.action, d.pid, d.remediation) == (MITIGATE, 4711, "kill")


def test_sin_lista_de_pids_no_se_filtra():
    """Permite usar el parser suelto, por ejemplo desde un test o una herramienta."""
    assert parse_decision("DECISION: MITIGATE pid=999 action=kill").pid == 999


# ── Regresión 4: INVALID no es NOTHING ─────────────────────────

@pytest.mark.parametrize("texto", [
    "",
    "No sé qué hacer con esto.",
    "The process is suspicious but I cannot decide.",
    "DECISION: PROBABLY",
    "DECISION: MITIGATE pid=abc action=kill",
    "DECISION: MITIGATE pid=4711 action=destroy",
])
def test_una_respuesta_inutilizable_es_invalid(texto):
    """Antes todo esto colapsaba en NOTHING y falseaba la tasa de falsos negativos."""
    assert parse_decision(texto, allowed_pids={4711}).action == INVALID


def test_invalid_explica_el_motivo():
    assert parse_decision("").detail
    assert parse_decision("bla bla").detail


# ── Adornos que añaden los modelos ─────────────────────────────

@pytest.mark.parametrize("linea", [
    "DECISION: NOTHING",
    "**DECISION: NOTHING**",
    "- DECISION: NOTHING",
    "> DECISION: NOTHING",
    "`DECISION: NOTHING`",
    "DECISION: NOTHING.",
    "   decision: nothing   ",
    "DECISION:NOTHING",
])
def test_tolera_markdown_y_variantes(linea):
    assert parse_decision(linea).action == NOTHING


def test_tolera_adornos_en_una_mitigacion():
    d = parse_decision("**DECISION: MITIGATE pid=4711 action=freeze**",
                       allowed_pids={4711})
    assert (d.action, d.pid, d.remediation) == (MITIGATE, 4711, "freeze")


def test_investigate_se_parsea():
    d = parse_decision("DECISION: INVESTIGATE pid=4711", allowed_pids={4711})
    assert (d.action, d.pid) == (INVESTIGATE, 4711)


# ── Salida estructurada ────────────────────────────────────────

def test_estructurada_basica():
    d = from_structured(
        {"reasoning": "…", "action": "MITIGATE", "pid": 4711, "remediation": "kill"},
        {4711})
    assert (d.action, d.pid, d.remediation, d.source) == (MITIGATE, 4711, "kill",
                                                          "structured")


def test_estructurada_ignora_remediation_si_la_accion_no_es_mitigate():
    """Incoherencia observada de verdad: NOTHING junto a remediation=freeze.

    El esquema acota cada campo por separado, pero no obliga a que sean coherentes
    entre sí.
    """
    d = from_structured({"action": "NOTHING", "pid": 4711, "remediation": "freeze"},
                        {4711})
    assert d.action == NOTHING
    assert d.remediation is None


def test_estructurada_sin_pid_en_una_accion_que_lo_exige():
    d = from_structured({"action": "MITIGATE", "pid": None}, {4711})
    assert d.action == INVALID


def test_estructurada_rechaza_pid_alucinado():
    d = from_structured({"action": "MITIGATE", "pid": 1, "remediation": "kill"}, {4711})
    assert d.action == INVALID


def test_estructurada_sin_remediation_elige_la_accion_reversible():
    """Congelar se deshace; matar no. Misma política asimétrica que las salvaguardas."""
    d = from_structured({"action": "MITIGATE", "pid": 4711}, {4711})
    assert d.remediation == "freeze"


def test_estructurada_con_accion_desconocida_no_es_utilizable():
    assert from_structured({"action": "PANIC", "pid": 4711}, {4711}) is None


def test_el_esquema_puede_prohibir_investigate():
    """En la ronda 2 ya no procede investigar más."""
    assert INVESTIGATE not in schema(allow_investigate=False)["properties"]["action"]["enum"]
    assert INVESTIGATE in schema()["properties"]["action"]["enum"]


@pytest.mark.parametrize("campo", ["reasoning", "action", "pid", "remediation"])
def test_el_esquema_exige_todos_los_campos(campo):
    """Regresión: un campo opcional es un campo que el modelo va a omitir.

    En la primera verificación de la Fase 2 el esquema solo exigía `reasoning` y
    `action`. El modelo respondió `{"action": "INVESTIGATE"}` sin `pid`, dos veces
    seguidas, aunque citaba los PIDs en su propio razonamiento. Era válido contra
    aquel esquema y dejaba el ciclo entero en INVALID.
    """
    assert campo in schema()["required"]
    assert campo in schema(allow_investigate=False)["required"]


def test_pid_admite_null_para_poder_expresar_no_aplica():
    """Obligatorio no es lo mismo que no nulo: en NOTHING no hay PID que dar."""
    assert "null" in schema()["properties"]["pid"]["type"]


def test_el_esquema_acota_el_pid_a_los_presentados():
    """Regresión: el modelo devolvía el `ppid` en lugar del `pid`.

    La telemetría muestra `pid=108630 ppid=108629` y respondía `108629`, de forma
    sistemática y también en el reintento. No era alucinación sino confusión entre
    dos campos numéricos contiguos. Acotar el campo por `enum` lo hace imposible:
    la gramática derivada del esquema no puede generar otro valor.
    """
    campo = schema(allowed_pids={108630, 108640})["properties"]["pid"]

    assert campo["enum"] == [108630, 108640, None]
    assert 108629 not in campo["enum"], "el ppid contiguo debe quedar fuera"


def test_sin_lista_de_pids_el_campo_queda_abierto():
    """Permite usar el esquema suelto, sin una telemetría concreta detrás."""
    assert "enum" not in schema()["properties"]["pid"]
    assert "enum" not in schema(allowed_pids=set())["properties"]["pid"]


def test_null_sigue_permitido_al_acotar():
    """Un veredicto NOTHING no lleva PID: el enum tiene que admitir null."""
    assert None in schema(allowed_pids={1234})["properties"]["pid"]["enum"]


# ── decide(): elección de vía ──────────────────────────────────

def test_decide_prefiere_la_via_estructurada():
    r = LLMResult(text="DECISION: NOTHING",
                  data={"action": "MITIGATE", "pid": 4711, "remediation": "kill"})
    d = decide(r, {4711})
    assert (d.action, d.source) == (MITIGATE, "structured")


def test_decide_recurre_al_parser_si_no_hay_estructura():
    d = decide(LLMResult(text="DECISION: NOTHING"), {4711})
    assert (d.action, d.source) == (NOTHING, "parsed")


def test_decide_recurre_al_parser_si_la_estructura_no_sirve():
    r = LLMResult(text="DECISION: NOTHING", data={"action": "PANIC"})
    assert decide(r, {4711}).source == "parsed"


def test_decide_con_error_del_modelo_es_invalid():
    d = decide(LLMResult(error="timeout tras 180s"), {4711})
    assert d.action == INVALID
    assert "timeout" in d.detail


def test_decide_sin_resultado_es_invalid():
    assert decide(None, {4711}).action == INVALID


def test_is_actionable():
    assert Decision(MITIGATE, pid=1).is_actionable
    assert Decision(INVESTIGATE, pid=1).is_actionable
    assert not Decision(NOTHING).is_actionable
    assert not Decision(INVALID).is_actionable
    assert not Decision(MITIGATE).is_actionable
