"""Instala o hook de pre-commit do git que recusa commits com segredo."""
import os
import subprocess

from .scanner import SecretscanError, _git_exe

MARCA = "# secrets-scanner pre-commit hook"


def _script(app_py):
    app = app_py.replace("\\", "/")
    return (
        "#!/bin/sh\n"
        f"{MARCA}\n"
        f'SCANNER="{app}"\n'
        "for PY in python3 python py; do\n"
        '  if command -v "$PY" >/dev/null 2>&1; then\n'
        '    exec "$PY" "$SCANNER" scan-staged\n'
        "  fi\n"
        "done\n"
        'echo "secrets-scanner: Python não encontrado; commit recusado por segurança." >&2\n'
        'echo "Para pular a verificação uma vez: git commit --no-verify" >&2\n'
        "exit 1\n"
    )


def _hooks_dir(repo):
    r = subprocess.run([_git_exe(), "-C", repo, "rev-parse", "--git-path", "hooks"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SecretscanError(f"{repo} não é um repositório git (rode `git init` antes)")
    pasta = r.stdout.strip()
    return pasta if os.path.isabs(pasta) else os.path.join(repo, pasta)


def instalar(repo, app_py, force=False):
    pasta = _hooks_dir(repo)
    os.makedirs(pasta, exist_ok=True)
    destino = os.path.join(pasta, "pre-commit")
    if os.path.exists(destino):
        with open(destino, encoding="utf-8", errors="replace") as f:
            nosso = MARCA in f.read()
        if not nosso and not force:
            raise SecretscanError(f"já existe um pre-commit que não é deste projeto: {destino} "
                                  "(use --force para substituir)")
    with open(destino, "w", encoding="utf-8", newline="\n") as f:  # LF: o sh do Git for Windows exige
        f.write(_script(os.path.abspath(app_py)))
    try:
        os.chmod(destino, 0o755)
    except OSError:
        pass
    return destino


def remover(repo):
    destino = os.path.join(_hooks_dir(repo), "pre-commit")
    if not os.path.exists(destino):
        return None
    with open(destino, encoding="utf-8", errors="replace") as f:
        if MARCA not in f.read():
            raise SecretscanError("o pre-commit existente não é deste projeto; não vou remover")
    os.remove(destino)
    return destino
