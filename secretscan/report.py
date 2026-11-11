"""Relatórios: texto, JSON, SARIF (GitHub code scanning) e JSONL para o painel Venator.

Nenhum formato recebe o segredo bruto: só `masked` e `snippet`, já mascarados.
"""
import json
from datetime import datetime, timezone

from . import __version__
from .model import SEVERIDADES, sev_rank
from .rules import RULES

ROTULO = {"critical": "CRÍTICO", "high": "ALTO", "medium": "MÉDIO", "low": "BAIXO"}
COR = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
RESET, DIM = "\033[0m", "\033[2m"


def contagem(findings):
    c = {s: 0 for s in reversed(SEVERIDADES)}
    for f in findings:
        c[f.severity] += 1
    return c


def _ordenar(findings):
    return sorted(findings, key=lambda f: (-sev_rank(f.severity), f.file, f.line))


def render_text(findings, result=None, suprimidos=0, cor=False):
    def c(sev, txt):
        return f"{COR[sev]}{txt}{RESET}" if cor else txt

    linhas = []
    for f in _ordenar(findings):
        linhas.append(f"{c(f.severity, '[' + ROTULO[f.severity] + ']')} {f.rule_id}  {f.file}:{f.line}")
        linhas.append(f"    {f.title}: {f.masked}")
        linhas.append(f"    {(DIM if cor else '')}{f.snippet}{RESET if cor else ''}")
        if f.commit:
            quando = (f.date or "")[:10]
            linhas.append(f"    introduzido no commit {f.commit[:8]} ({f.author}, {quando})")
            if f.removed:
                linhas.append("    >> já foi apagado do código, mas ainda está no histórico do git: "
                              "trate como vazado")
        linhas.append("")
    cont = contagem(findings)
    resumo = ", ".join(f"{cont[s]} {ROTULO[s].lower()}" for s in reversed(SEVERIDADES))
    if result is not None:
        linhas.append(f"{result.files_scanned} arquivo(s) analisado(s); {result.skipped_binary} binário(s) e "
                      f"{result.skipped_large} grande(s) ignorado(s).")
    if suprimidos:
        linhas.append(f"{suprimidos} achado(s) conhecido(s) suprimido(s) pela linha de base.")
    linhas.append(f"{len(findings)} achado(s): {resumo}." if findings else "Nenhum achado.")
    linhas.append("Aviso: é heurística. \"Nada encontrado\" não prova que não há segredos.")
    return "\n".join(linhas) + "\n"


def to_dict(findings, result=None, suprimidos=0):
    dados = {
        "tool": "secrets-scanner", "version": __version__,
        "summary": {"total": len(findings), "by_severity": contagem(findings), "suppressed": suprimidos},
        "findings": [f.to_dict() for f in _ordenar(findings)],
    }
    if result is not None:
        dados["summary"].update(files_scanned=result.files_scanned, skipped_binary=result.skipped_binary,
                                skipped_large=result.skipped_large)
    return dados


def render_json(findings, result=None, suprimidos=0):
    return json.dumps(to_dict(findings, result, suprimidos), indent=2, ensure_ascii=False) + "\n"


_NIVEL_SARIF = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def render_sarif(findings):
    regras = [{"id": r.id, "name": r.id, "shortDescription": {"text": r.title},
               "defaultConfiguration": {"level": _NIVEL_SARIF[r.severity]}} for r in RULES]
    resultados = []
    for f in _ordenar(findings):
        msg = f"{f.title}: {f.masked}"
        if f.removed:
            msg += " (já apagado do código, mas ainda no histórico do git)"
        item = {
            "ruleId": f.rule_id, "level": _NIVEL_SARIF[f.severity], "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file.replace("\\", "/")},
                                                "region": {"startLine": max(f.line, 1)}}}],
        }
        if f.commit:
            item["properties"] = {"commit": f.commit, "removedFromCode": bool(f.removed)}
        resultados.append(item)
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "secrets-scanner", "version": __version__,
                                      "rules": regras}}, "results": resultados}],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"


def render_venator(findings):
    """JSONL no formato genérico que o Venator já importa (source/type/severity/message/ts)."""
    agora = datetime.now(timezone.utc).isoformat()
    linhas = []
    for f in _ordenar(findings):
        local = f"{f.file}:{f.line}"
        msg = f"{f.title} em {local} ({f.masked})"
        if f.removed:
            msg += " — já apagado do código, mas ainda no histórico do git"
        rec = {"source": "secretscan", "type": "secret_leak", "severity": f.severity, "ts": f.date or agora,
               "message": msg, "rule": f.rule_id, "file": f.file, "line": f.line, "masked": f.masked}
        if f.commit:
            rec.update(commit=f.commit, removed_from_code=bool(f.removed))
        linhas.append(json.dumps(rec, ensure_ascii=False))
    return "\n".join(linhas) + ("\n" if linhas else "")


FORMATOS = ("text", "json", "sarif", "venator")
