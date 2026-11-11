import contextlib
import io
import json
import os
import tempfile
import unittest

from secretscan.cli import main
from tests.helpers import amostras
from tests.test_scan_files import escrever


def rodar(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        codigo = main(list(argv))
    return codigo, out.getvalue(), err.getvalue()


class Cli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.addCleanup(self.tmp.cleanup)

    def test_codigos_de_saida(self):
        escrever(self.d, "limpo.py", "x = 1\n")
        self.assertEqual(rodar("scan", self.d)[0], 0)
        escrever(self.d, "a.py", amostras()["aws-access-key-id"])
        self.assertEqual(rodar("scan", self.d)[0], 1)

    def test_fail_on(self):
        escrever(self.d, "a.py", amostras()["cpf"])  # severidade média
        self.assertEqual(rodar("scan", self.d, "--fail-on", "high")[0], 0)
        self.assertEqual(rodar("scan", self.d, "--fail-on", "medium")[0], 1)

    def test_formato_json_e_arquivo_de_saida(self):
        escrever(self.d, "a.py", amostras()["github-token"])
        codigo, out, _ = rodar("scan", self.d, "--format", "json")
        self.assertEqual(codigo, 1)
        self.assertEqual(json.loads(out)["summary"]["total"], 1)
        destino = os.path.join(self.d, "saida.sarif")
        codigo, out, err = rodar("scan", self.d, "--format", "sarif", "-o", destino)
        self.assertEqual(out, "")
        with open(destino, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["version"], "2.1.0")

    def test_baseline_pela_cli(self):
        escrever(self.d, "a.py", amostras()["github-token"])
        bl = os.path.join(self.d, "base.json")
        self.assertEqual(rodar("baseline", self.d, "-o", bl)[0], 0)
        self.assertEqual(rodar("scan", self.d, "--baseline", bl)[0], 0)

    def test_erros_de_uso_voltam_2(self):
        self.assertEqual(rodar("scan", os.path.join(self.d, "nada"))[0], 2)
        self.assertEqual(rodar("scan", self.d, "--history")[0], 2)  # não é repositório git

    def test_lista_de_regras(self):
        codigo, out, _ = rodar("rules")
        self.assertEqual(codigo, 0)
        self.assertIn("23 regras", out)


if __name__ == "__main__":
    unittest.main()
