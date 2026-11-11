"""Linha de base: achados conhecidos que não devem mais ser reportados.

Guarda só o HMAC-SHA256 do segredo (nunca o segredo). A chave do HMAC fica numa chave local, fora do
que se commita (dentro de .git/ quando existe), para que ninguém consiga testar palpites de senha
contra a linha de base.
"""
import hashlib
import hmac
import json
import os
import secrets

BASELINE_PADRAO = ".secretscan-baseline.json"


def _caminho_chave(baseline_path):
    pasta = os.path.dirname(os.path.abspath(baseline_path))
    git = os.path.join(pasta, ".git")
    if os.path.isdir(git):
        return os.path.join(git, "secretscan.key")
    return os.path.join(pasta, ".secretscan.key")


def carregar_chave(baseline_path, criar=False):
    cam = _caminho_chave(baseline_path)
    try:
        with open(cam, encoding="ascii") as f:
            return f.read().strip().encode("ascii")
    except OSError:
        if not criar:
            return None
    chave = secrets.token_hex(32)
    with open(cam, "w", encoding="ascii") as f:
        f.write(chave)
    try:
        os.chmod(cam, 0o600)
    except OSError:
        pass
    return chave.encode("ascii")


def impressao(chave, rule_id, secret):
    return hmac.new(chave, (rule_id + "\0" + secret).encode("utf-8", "replace"), hashlib.sha256).hexdigest()


def criar(findings, baseline_path):
    chave = carregar_chave(baseline_path, criar=True)
    entradas = sorted(
        ({"rule": f.rule_id, "fp": impressao(chave, f.rule_id, f.secret), "file": f.file} for f in findings),
        key=lambda e: (e["rule"], e["fp"]))
    with open(baseline_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"version": 1, "entries": entradas}, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return len(entradas)


def filtrar(findings, baseline_path):
    """Devolve (achados novos, quantos foram suprimidos pela linha de base)."""
    try:
        with open(baseline_path, encoding="utf-8") as f:
            dados = json.load(f)
    except (OSError, ValueError):
        return findings, 0
    chave = carregar_chave(baseline_path)
    if chave is None:
        return findings, 0
    conhecidos = {(e.get("rule"), e.get("fp")) for e in dados.get("entries", [])}
    novos = [f for f in findings if (f.rule_id, impressao(chave, f.rule_id, f.secret)) not in conhecidos]
    return novos, len(findings) - len(novos)
