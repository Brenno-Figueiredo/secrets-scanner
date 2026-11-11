"""Núcleo: varre texto, arquivos, o que está no index do git e o histórico inteiro."""
import fnmatch
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional

from .model import Finding, mask_secret
from .rules import RULES

IGNORE_MARK = "secretscan:ignore"
DIRS_IGNORADOS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", "dist", "build",
                  ".mypy_cache", ".pytest_cache", ".idea", ".vscode"}
ARQUIVOS_IGNORADOS = {".secretscan-baseline.json", ".secretscan.key"}
MAX_BYTES = 1024 * 1024
JANELA, PASSO = 4000, 3800  # linhas enormes (JS minificado) são lidas em janelas com sobreposição
COMMIT_MARK = "@@SECRETSCAN-COMMIT@@"


class SecretscanError(Exception):
    """Erro de uso (git ausente, pasta que não é repositório...)."""


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    skipped_binary: int = 0
    skipped_large: int = 0

    def merge(self, other):
        self.findings.extend(other.findings)
        self.files_scanned += other.files_scanned
        self.skipped_binary += other.skipped_binary
        self.skipped_large += other.skipped_large


def _hits(trecho):
    achados, tomados = [], []
    for rule in RULES:
        for pat, grp in rule.patterns:
            for m in pat.finditer(trecho):
                secret = m.group(grp)
                if not secret:
                    continue
                s, e = m.span(grp)
                if any(s < te and ts < e for ts, te in tomados):
                    continue
                if rule.validate and not rule.validate(secret, trecho, m):
                    continue
                tomados.append((s, e))
                achados.append((s, e, rule, secret))
    return achados


def scan_line(line, lineno, path):
    """Procura segredos numa linha. O trecho exibido tem TODOS os segredos da linha mascarados."""
    if IGNORE_MARK in line:
        return []
    achados, vistos = [], set()
    for off in range(0, max(len(line), 1), PASSO):
        for s, e, rule, secret in _hits(line[off:off + JANELA]):
            chave = (rule.id, off + s, off + e)
            if chave not in vistos:
                vistos.add(chave)
                achados.append((off + s, off + e, rule, secret))
    if not achados:
        return []
    achados.sort(key=lambda h: h[0])
    mascarada = line
    for s, e, rule, secret in sorted(achados, key=lambda h: h[0], reverse=True):
        mascarada = mascarada[:s] + mask_secret(rule.id, secret) + mascarada[e:]
    out = []
    for s, e, rule, secret in achados:
        ini = max(0, s - 50)
        trecho = mascarada[ini:ini + 160].strip()
        if ini > 0:
            trecho = "…" + trecho
        out.append(Finding(rule.id, rule.title, rule.severity, path, lineno,
                           mask_secret(rule.id, secret), trecho, secret=secret))
    return out


def scan_text(text, path="<texto>"):
    achados = []
    for n, line in enumerate(text.splitlines(), 1):
        achados.extend(scan_line(line, n, path))
    return achados


def ignorado(relpath, excludes=()):
    partes = relpath.replace("\\", "/").split("/")
    if any(p in DIRS_IGNORADOS for p in partes[:-1]) or partes[-1] in ARQUIVOS_IGNORADOS:
        return True
    return any(fnmatch.fnmatch(relpath, g) or fnmatch.fnmatch(partes[-1], g) for g in excludes)


def _rel(caminho, base):
    try:
        r = os.path.relpath(caminho, base)
    except ValueError:
        r = caminho
    return r.replace(os.sep, "/")


def _scan_arquivo(caminho, rel, result):
    try:
        tam = os.path.getsize(caminho)
        if tam > MAX_BYTES:
            result.skipped_large += 1
            return
        with open(caminho, "rb") as f:
            dados = f.read()
    except OSError:
        return
    if b"\0" in dados[:8192]:
        result.skipped_binary += 1
        return
    result.files_scanned += 1
    result.findings.extend(scan_text(dados.decode("utf-8-sig", errors="replace"), rel))


def scan_path(path, excludes=()):
    """Varre um arquivo ou uma pasta (sem seguir links simbólicos)."""
    result = ScanResult()
    if os.path.isfile(path):
        _scan_arquivo(path, os.path.basename(path), result)
    elif os.path.isdir(path):
        for raiz, dirs, nomes in os.walk(path):
            dirs[:] = sorted(d for d in dirs if d not in DIRS_IGNORADOS
                             and not os.path.islink(os.path.join(raiz, d)))
            for nome in sorted(nomes):
                cam = os.path.join(raiz, nome)
                rel = _rel(cam, path)
                if os.path.islink(cam) or ignorado(rel, excludes):
                    continue
                _scan_arquivo(cam, rel, result)
    else:
        raise SecretscanError(f"caminho não encontrado: {path}")
    result.findings.sort(key=lambda f: (f.file, f.line))
    return result


# ----------------------------------------------------------------------------- git

def _git_exe():
    exe = shutil.which("git")
    if not exe:
        raise SecretscanError("git não encontrado no PATH")
    return exe


def is_git_repo(repo):
    try:
        r = subprocess.run([_git_exe(), "-C", repo, "rev-parse", "--is-inside-work-tree"],
                           capture_output=True, text=True)
    except OSError:
        return False
    return r.returncode == 0 and r.stdout.strip() == "true"


def _linhas_do_git(args, repo):
    # stderr vai para um arquivo temporário: ler os dois pipes ao mesmo tempo poderia travar.
    with tempfile.TemporaryFile() as erro:
        proc = subprocess.Popen([_git_exe(), "-C", repo, "-c", "core.quotepath=off"] + args,
                                stdout=subprocess.PIPE, stderr=erro)
        try:
            for bruto in proc.stdout:
                yield bruto.decode("utf-8", errors="replace").rstrip("\r\n")
        finally:
            proc.stdout.close()
            codigo = proc.wait()
        if codigo != 0:
            erro.seek(0)
            msg = erro.read().decode("utf-8", errors="replace").strip()
            raise SecretscanError(f"git falhou: {msg or 'sem mensagem'}")


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)")


def _linhas_adicionadas(linhas, excludes=()):
    """Lê um diff (-U0) e devolve (commit_meta, arquivo, nº da linha, texto) das linhas ADICIONADAS."""
    meta, path, lineno, cabecalho = None, None, 0, False
    for linha in linhas:
        if linha.startswith(COMMIT_MARK):
            partes = linha[len(COMMIT_MARK):].split("\t")
            meta = (partes + ["", "", ""])[:3]
            path, cabecalho = None, False
        elif linha.startswith("diff --git "):
            path, cabecalho = None, True
        elif cabecalho and linha.startswith("+++ "):
            alvo = linha[4:].rstrip("\t")
            path = alvo[2:] if alvo.startswith("b/") else None
            if path and ignorado(path, excludes):
                path = None
        elif linha.startswith("@@ "):
            cabecalho = False
            m = _HUNK.match(linha)
            lineno = int(m.group(1)) if m else 0
        elif not cabecalho and linha.startswith("+") and path:
            yield meta, path, lineno, linha[1:]
            lineno += 1


def scan_staged(repo=".", excludes=()):
    """Varre só o que está no index (o que entraria no commit)."""
    linhas = _linhas_do_git(["diff", "--cached", "-U0", "--no-color", "--no-ext-diff", "--no-textconv",
                             "--diff-filter=ACMR"], repo)
    achados = []
    for _, path, n, texto in _linhas_adicionadas(linhas, excludes):
        achados.extend(scan_line(texto, n, path))
    return achados


def scan_history(repo, tree_findings, max_commits: Optional[int] = None, excludes=()):
    """Varre as linhas adicionadas em todos os commits.

    Cada segredo é reportado uma vez, no commit mais antigo que o introduziu. Se ele ainda está na
    árvore de trabalho, o achado da árvore ganha os dados do commit; se não está, vira um achado
    novo marcado como "já apagado do código, mas ainda no histórico".
    """
    args = ["log", "--all", "-p", "-U0", "--no-color", "--no-ext-diff", "--no-textconv",
            f"--format={COMMIT_MARK}%H%x09%an%x09%aI"]
    if max_commits:
        args.append(f"--max-count={max_commits}")
    antigos = {}
    for meta, path, n, texto in _linhas_adicionadas(_linhas_do_git(args, repo), excludes):
        for f in scan_line(texto, n, path):
            f.commit, f.author, f.date = meta[0], meta[1], meta[2]
            antigos[f.chave()] = f  # o log vem do mais novo ao mais antigo: o último vence
    na_arvore = {}
    for f in tree_findings:
        na_arvore.setdefault(f.chave(), f)
    saida = list(tree_findings)
    for chave, f in antigos.items():
        if chave in na_arvore:
            atual = na_arvore[chave]
            atual.commit, atual.author, atual.date, atual.removed = f.commit, f.author, f.date, False
        else:
            f.removed = True
            saida.append(f)
    saida.sort(key=lambda x: (x.file, x.line))
    return saida
