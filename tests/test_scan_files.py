import json
import os
import tempfile
import unittest

from secretscan import baseline, report
from secretscan.scanner import SecretscanError, scan_path
from tests.helpers import amostras, rnd


def escrever(pasta, nome, conteudo, modo="w"):
    cam = os.path.join(pasta, nome)
    os.makedirs(os.path.dirname(cam), exist_ok=True)
    with open(cam, modo, **({"encoding": "utf-8"} if "b" not in modo else {})) as f:
        f.write(conteudo)
    return cam


class VarreduraDeArquivos(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.addCleanup(self.tmp.cleanup)

    def test_acha_com_arquivo_e_linha(self):
        escrever(self.d, "src/app.py", "x = 1\n" + amostras()["aws-access-key-id"] + "\n")
        r = scan_path(self.d)
        self.assertEqual([(f.rule_id, f.file, f.line) for f in r.findings],
                         [("aws-access-key-id", "src/app.py", 2)])

    def test_pastas_ignoradas_binarios_e_grandes(self):
        s = amostras()["aws-access-key-id"]
        escrever(self.d, "node_modules/x/a.js", s)
        escrever(self.d, ".git/config", s)
        escrever(self.d, "img.bin", b"\0\0" + s.encode(), "wb")
        escrever(self.d, "grande.txt", s + "\n" + "a" * (1024 * 1024 + 10))
        r = scan_path(self.d)
        self.assertEqual(r.findings, [])
        self.assertEqual(r.skipped_binary, 1)
        self.assertEqual(r.skipped_large, 1)

    def test_exclude(self):
        escrever(self.d, "tests/dados.txt", amostras()["aws-access-key-id"])
        self.assertEqual(scan_path(self.d, ["tests/*"]).findings, [])

    def test_bom_utf8_e_crlf(self):
        conteudo = "﻿" + amostras()["github-token"] + "\r\nresto\r\n"
        escrever(self.d, "a.txt", conteudo)
        self.assertEqual([f.line for f in scan_path(self.d).findings], [1])

    def test_link_simbolico_nao_e_seguido(self):
        fora = tempfile.TemporaryDirectory()
        self.addCleanup(fora.cleanup)
        escrever(fora.name, "s.txt", amostras()["aws-access-key-id"])
        try:
            os.symlink(os.path.join(fora.name, "s.txt"), os.path.join(self.d, "link.txt"))
            os.symlink(fora.name, os.path.join(self.d, "pasta"))
        except (OSError, NotImplementedError):
            self.skipTest("sem suporte a links simbólicos")
        self.assertEqual(scan_path(self.d).findings, [])

    def test_caminho_inexistente(self):
        with self.assertRaises(SecretscanError):
            scan_path(os.path.join(self.d, "nao-existe"))

    def test_arquivo_unico(self):
        cam = escrever(self.d, "a.txt", amostras()["npm-token"])
        self.assertEqual(len(scan_path(cam).findings), 1)


class NenhumRelatorioMostraSegredoInteiro(unittest.TestCase):
    def test_todos_os_formatos_e_a_linha_de_base(self):
        with tempfile.TemporaryDirectory() as d:
            for i, linha in enumerate(amostras().values()):
                escrever(d, f"f{i}.txt", linha + "\n")
            r = scan_path(d)
            self.assertGreaterEqual(len(r.findings), 23)
            saidas = [report.render_text(r.findings, r), report.render_json(r.findings, r),
                      report.render_sarif(r.findings), report.render_venator(r.findings)]
            bl = os.path.join(d, "base.json")
            baseline.criar(r.findings, bl)
            with open(bl, encoding="utf-8") as f:
                saidas.append(f.read())
            for f in r.findings:
                if f.rule_id in ("private-key", "cpf", "cnpj"):
                    continue  # cabeçalho PEM não é o segredo; CPF/CNPJ mostram só os 2 últimos dígitos
                for s in saidas:
                    self.assertNotIn(f.secret, s, f.rule_id)
            for f in r.findings:
                if f.rule_id in ("cpf", "cnpj"):
                    for s in saidas:
                        self.assertNotIn(f.secret, s)

    def test_formatos_sao_validos(self):
        with tempfile.TemporaryDirectory() as d:
            escrever(d, "a.py", amostras()["github-token"])
            r = scan_path(d)
            self.assertEqual(json.loads(report.render_json(r.findings, r))["summary"]["total"], 1)
            sarif = json.loads(report.render_sarif(r.findings))
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "github-token")
            self.assertEqual(sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
                             ["region"]["startLine"], 1)
            rec = json.loads(report.render_venator(r.findings).splitlines()[0])
            self.assertEqual((rec["source"], rec["type"], rec["severity"]), ("secretscan", "secret_leak", "critical"))


class LinhaDeBase(unittest.TestCase):
    def test_suprime_conhecidos_e_deixa_passar_novos(self):
        with tempfile.TemporaryDirectory() as d:
            escrever(d, "a.py", amostras()["github-token"] + "\n")
            bl = os.path.join(d, ".secretscan-baseline.json")
            self.assertEqual(baseline.criar(scan_path(d).findings, bl), 1)
            novos, sup = baseline.filtrar(scan_path(d).findings, bl)
            self.assertEqual((novos, sup), ([], 1))
            escrever(d, "b.py", "k = '" + "AKIA" + rnd(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 99) + "'\n")
            novos, sup = baseline.filtrar(scan_path(d).findings, bl)
            self.assertEqual((len(novos), sup), (1, 1))

    def test_sem_a_chave_local_nada_e_suprimido(self):
        with tempfile.TemporaryDirectory() as d:
            escrever(d, "a.py", amostras()["github-token"] + "\n")
            bl = os.path.join(d, "base.json")
            baseline.criar(scan_path(d).findings, bl)
            os.remove(os.path.join(d, ".secretscan.key"))
            novos, sup = baseline.filtrar(scan_path(d).findings, bl)
            self.assertEqual((len(novos), sup), (1, 0))

    def test_a_propria_linha_de_base_nao_e_varrida(self):
        with tempfile.TemporaryDirectory() as d:
            escrever(d, "a.py", amostras()["github-token"] + "\n")
            baseline.criar(scan_path(d).findings, os.path.join(d, ".secretscan-baseline.json"))
            self.assertEqual(len(scan_path(d).findings), 1)


if __name__ == "__main__":
    unittest.main()
