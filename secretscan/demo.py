"""Pasta de demonstração: só dados FALSOS, gerados na hora, para mostrar a interface sem expor nada real.

Os valores são montados por partes no código para que o próprio projeto não se acuse ao se varrer.
O CPF e o CNPJ são os exemplos públicos mais conhecidos de números de teste.
"""
import os
import random
import shutil
import stat
import subprocess

from .scanner import _git_exe

_ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _rnd(r, n, alfabeto=_ALNUM):
    return "".join(r.choice(alfabeto) for _ in range(n))


def _escrever(pasta, nome, texto):
    with open(os.path.join(pasta, nome), "w", encoding="utf-8", newline="\n") as f:
        f.write(texto)


def _git(pasta, *args):
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="Demo", GIT_AUTHOR_EMAIL="demo@example.org",
               GIT_COMMITTER_NAME="Demo", GIT_COMMITTER_EMAIL="demo@example.org")
    subprocess.run([_git_exe(), "-C", pasta, "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"] + list(args),
                   check=True, capture_output=True, env=env)


def criar(pasta):
    """Cria a pasta de demonstração. Devolve True se conseguiu também criar um histórico git."""
    r = random.Random(2026)
    token_gh = "gh" + "p_" + _rnd(r, 36)
    _escrever(pasta, "legacy_deploy.py",
              "import requests\n\n# versão antiga: o token estava escrito aqui\n"
              f'TOKEN = "{token_gh}"\n\n\ndef publicar(pacote):\n    return requests.post(URL, data=pacote)\n')
    _escrever(pasta, "config.py",
              "import os\n\n"
              f'AWS_ACCESS_KEY_ID = "{"AKIA" + _rnd(r, 16, _UPPER)}"\n'
              f'aws_secret_access_key = "{_rnd(r, 40)}"\n'
              f'db_password = "{_rnd(r, 14)}"\n'
              'DEBUG = os.environ.get("DEBUG", "0")\n')
    _escrever(pasta, ".env", f"DB_PASSWORD={_rnd(r, 16)}\nAPI_URL=https://api.exemplo.local\n")
    _escrever(pasta, "pagamento.js", f'const stripe = require("stripe")("{"sk" + "_live_" + _rnd(r, 30)}");\n')
    _escrever(pasta, "docker-compose.yml",
              f"services:\n  app:\n    environment:\n      DATABASE_URL: postgres://app:{_rnd(r, 12)}@db:5432/prod\n")
    _escrever(pasta, "chave.pem", "-----" + "BEGIN " + "RSA PRIVATE KEY-----\n(conteúdo omitido na demonstração)\n")
    _escrever(pasta, "clientes.csv",
              "nome,cpf,empresa,cnpj\n"
              f"Cliente Exemplo,{'529.982.247' + '-25'},Empresa Exemplo,{'11.222.333' + '/0001-81'}\n")
    _escrever(pasta, "README.md", "# Projeto de demonstração\n\nTodos os dados desta pasta são falsos.\n")
    try:
        _git(pasta, "init", "-q", "-b", "main")
        _git(pasta, "add", "-A")
        _git(pasta, "commit", "-q", "-m", "primeira versão")
        _escrever(pasta, "legacy_deploy.py",
                  "import os\n\nimport requests\n\nTOKEN = os.environ[\"DEPLOY_TOKEN\"]\n\n\n"
                  "def publicar(pacote):\n    return requests.post(URL, data=pacote)\n")
        _git(pasta, "commit", "-q", "-am", "tira o token do código")
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def apagar(pasta):
    def _forcar(func, caminho, _):
        os.chmod(caminho, stat.S_IWRITE)
        func(caminho)
    shutil.rmtree(pasta, onerror=_forcar)
