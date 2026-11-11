import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from secretscan import hook
from secretscan.scanner import SecretscanError, scan_history, scan_path, scan_staged
from tests.helpers import amostras

GIT = shutil.which("git")
APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")


def git(repo, *args, check=True):
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_AUTHOR_NAME="Teste", GIT_AUTHOR_EMAIL="t@example.org",
               GIT_COMMITTER_NAME="Teste", GIT_COMMITTER_EMAIL="t@example.org")
    r = subprocess.run([GIT, "-C", repo, "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"] + list(args),
                       capture_output=True, text=True, env=env)
    if check and r.returncode != 0:
        raise AssertionError(r.stderr)
    return r


def escrever(repo, nome, conteudo):
    cam = os.path.join(repo, nome)
    os.makedirs(os.path.dirname(cam), exist_ok=True)
    with open(cam, "w", encoding="utf-8", newline="\n") as f:
        f.write(conteudo)


@unittest.skipUnless(GIT, "git não instalado")
class Historico(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = self.tmp.name
        self.addCleanup(self.tmp.cleanup)
        git(self.repo, "init", "-q", "-b", "main")

    def commit(self, msg):
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", msg)
        return git(self.repo, "rev-parse", "HEAD").stdout.strip()

    def test_segredo_apagado_continua_no_historico(self):
        escrever(self.repo, "app.py", "x = 1\n" + amostras()["github-token"] + "\n")
        sha = self.commit("adiciona token")
        escrever(self.repo, "app.py", "x = 1\n")
        self.commit("remove token")
        tree = scan_path(self.repo).findings
        self.assertEqual(tree, [])
        achados = scan_history(self.repo, tree)
        self.assertEqual(len(achados), 1)
        f = achados[0]
        self.assertEqual((f.rule_id, f.file, f.line, f.commit, f.removed), ("github-token", "app.py", 2, sha, True))

    def test_segredo_ainda_presente_ganha_o_commit_de_origem(self):
        escrever(self.repo, "app.py", amostras()["aws-access-key-id"] + "\n")
        sha = self.commit("adiciona chave")
        escrever(self.repo, "outro.py", "y = 2\n")
        self.commit("outro")
        achados = scan_history(self.repo, scan_path(self.repo).findings)
        self.assertEqual(len(achados), 1)
        self.assertEqual((achados[0].commit, achados[0].removed), (sha, False))

    def test_commit_mais_antigo_vence_e_dedup(self):
        s = amostras()["github-token"]
        escrever(self.repo, "a.py", s + "\n")
        primeiro = self.commit("primeiro")
        escrever(self.repo, "b.py", s + "\n")
        self.commit("copia")
        achados = scan_history(self.repo, [])
        self.assertEqual(len(achados), 1)
        self.assertEqual(achados[0].commit, primeiro)

    def test_conteudo_que_parece_cabecalho_de_diff(self):
        # linha adicionada que começa com "++" aparece no diff como "+++ ..."
        escrever(self.repo, "a.txt", "++ " + amostras()["github-token"] + "\n")
        self.commit("x")
        achados = scan_history(self.repo, [])
        self.assertEqual([f.rule_id for f in achados], ["github-token"])

    def test_nome_de_arquivo_com_espaco_e_acento(self):
        escrever(self.repo, "pasta com espaço/relatório final.txt", amostras()["npm-token"] + "\n")
        self.commit("x")
        self.assertEqual(scan_history(self.repo, [])[0].file, "pasta com espaço/relatório final.txt")

    def test_max_commits(self):
        escrever(self.repo, "a.py", amostras()["github-token"] + "\n")
        self.commit("antigo")
        escrever(self.repo, "b.py", "ok\n")
        self.commit("recente")
        self.assertEqual(scan_history(self.repo, [], max_commits=1), [])

    def test_pasta_que_nao_e_repositorio(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SecretscanError):
                scan_history(d, [])


@unittest.skipUnless(GIT, "git não instalado")
class IndexEHook(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = self.tmp.name
        self.addCleanup(self.tmp.cleanup)
        git(self.repo, "init", "-q", "-b", "main")

    def test_scan_staged_so_olha_o_que_vai_no_commit(self):
        escrever(self.repo, "ok.py", "a = 1\n")
        escrever(self.repo, "ruim.py", amostras()["github-token"] + "\n")
        git(self.repo, "add", "ok.py")
        self.assertEqual(scan_staged(self.repo), [])
        git(self.repo, "add", "ruim.py")
        achados = scan_staged(self.repo)
        self.assertEqual([(f.file, f.line) for f in achados], [("ruim.py", 1)])

    def test_hook_recusa_commit_com_segredo_e_aceita_limpo(self):
        destino = hook.instalar(self.repo, APP)
        with open(destino, "rb") as f:
            self.assertNotIn(b"\r\n", f.read(), "o hook precisa usar quebras de linha LF")
        escrever(self.repo, "ruim.py", amostras()["aws-access-key-id"] + "\n")
        git(self.repo, "add", "ruim.py")
        r = git(self.repo, "commit", "-q", "-m", "x", check=False)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("Commit recusado", r.stderr)
        self.assertEqual(git(self.repo, "rev-list", "--all", "--count", check=False).stdout.strip() or "0", "0")
        git(self.repo, "reset", "-q", "ruim.py")
        os.remove(os.path.join(self.repo, "ruim.py"))
        escrever(self.repo, "limpo.py", "print('oi')\n")
        git(self.repo, "add", "limpo.py")
        r = git(self.repo, "commit", "-q", "-m", "limpo", check=False)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_hook_nao_sobrescreve_hook_alheio_e_remove_so_o_proprio(self):
        pasta = os.path.join(self.repo, ".git", "hooks")
        os.makedirs(pasta, exist_ok=True)
        alheio = os.path.join(pasta, "pre-commit")
        with open(alheio, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        with self.assertRaises(SecretscanError):
            hook.instalar(self.repo, APP)
        with self.assertRaises(SecretscanError):
            hook.remover(self.repo)
        hook.instalar(self.repo, APP, force=True)
        self.assertEqual(hook.remover(self.repo), alheio)
        self.assertIsNone(hook.remover(self.repo))

    def test_hook_em_pasta_sem_git(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SecretscanError):
                hook.instalar(d, APP)


if __name__ == "__main__":
    unittest.main()
