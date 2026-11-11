import http.client
import json
import os
import re
import shutil
import tempfile
import threading
import unittest

from secretscan import demo, gui
from tests.helpers import amostras
from tests.test_scan_files import escrever

GIT = shutil.which("git")


class GuiBase(unittest.TestCase):
    def setUp(self):
        self.srv = gui.make_server(0, ".")
        self.porta = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self._parar)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _parar(self):
        self.srv.shutdown()
        self.srv.server_close()

    def req(self, metodo, rota, corpo=None, token=True, headers=None):
        cx = http.client.HTTPConnection("127.0.0.1", self.porta, timeout=20)
        h = dict(headers or {})
        if token is True:
            h["X-Token"] = self.srv.token
        elif token:
            h["X-Token"] = token
        dados = None
        if corpo is not None:
            dados = corpo if isinstance(corpo, bytes) else json.dumps(corpo).encode()
            h["Content-Type"] = "application/json"
        cx.request(metodo, rota, body=dados, headers=h)
        r = cx.getresponse()
        texto = r.read().decode("utf-8")
        cx.close()
        return r.status, r, texto


class Seguranca(GuiBase):
    def test_pagina_traz_token_e_cabecalhos_de_protecao(self):
        status, r, corpo = self.req("GET", "/", token=False)
        self.assertEqual(status, 200)
        self.assertIn(self.srv.token, corpo)
        self.assertNotIn("__CONFIG__", corpo)
        self.assertIn("default-src 'none'", r.getheader("Content-Security-Policy"))
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")

    def test_rota_inexistente(self):
        self.assertEqual(self.req("GET", "/etc/passwd", token=False)[0], 404)

    def test_post_sem_token_ou_com_token_errado(self):
        self.assertEqual(self.req("POST", "/api/scan", {"path": self.tmp.name}, token=False)[0], 403)
        self.assertEqual(self.req("POST", "/api/scan", {"path": self.tmp.name}, token="errado")[0], 403)

    def test_host_estranho_e_origem_estranha_sao_barrados(self):
        self.assertEqual(self.req("GET", "/", token=False, headers={"Host": "evil.example"})[0], 403)
        self.assertEqual(self.req("POST", "/api/scan", {"path": self.tmp.name},
                                  headers={"Host": "evil.example"})[0], 403)
        self.assertEqual(self.req("POST", "/api/scan", {"path": self.tmp.name},
                                  headers={"Origin": "http://evil.example"})[0], 403)

    def test_corpo_invalido_e_grande_demais(self):
        self.assertEqual(self.req("POST", "/api/scan", b"isso nao e json")[0], 400)
        self.assertEqual(self.req("POST", "/api/scan", b"[1, 2]")[0], 400)
        self.assertEqual(self.req("POST", "/api/scan", b"x" * (gui.MAX_CORPO + 10))[0], 413)
        self.assertEqual(self.req("POST", "/api/scan", {"path": self.tmp.name, "exclude": "tudo"})[0], 400)

    def test_servidor_so_escuta_em_localhost(self):
        self.assertEqual(self.srv.server_address[0], "127.0.0.1")

    def test_pagina_nao_carrega_nada_de_fora(self):
        with open(gui.PAGINA, encoding="utf-8") as f:
            self.assertEqual(re.findall(r"https?://", f.read()), [])


class Varredura(GuiBase):
    def test_varredura_devolve_achados_sem_o_segredo_inteiro(self):
        escrever(self.tmp.name, "a.py", amostras()["github-token"] + "\n")
        status, _, texto = self.req("POST", "/api/scan", {"path": self.tmp.name, "history": False})
        self.assertEqual(status, 200)
        dados = json.loads(texto)
        self.assertEqual(dados["report"]["summary"]["total"], 1)
        self.assertEqual(dados["report"]["findings"][0]["rule"], "github-token")
        self.assertIn("runs", json.loads(dados["sarif"]))
        self.assertIn('"source": "secretscan"', dados["venator"])
        segredo = amostras()["github-token"].split("= ")[1]
        self.assertNotIn(segredo, texto)

    def test_aspas_no_caminho_sao_aceitas(self):
        escrever(self.tmp.name, "a.py", "x = 1\n")
        status, _, _ = self.req("POST", "/api/scan", {"path": '"' + self.tmp.name + '"'})
        self.assertEqual(status, 200)

    def test_pasta_inexistente_e_historico_fora_de_repo(self):
        status, _, texto = self.req("POST", "/api/scan", {"path": os.path.join(self.tmp.name, "nada")})
        self.assertEqual(status, 400)
        self.assertIn("não encontrada", json.loads(texto)["error"])
        if GIT:
            status, _, texto = self.req("POST", "/api/scan", {"path": self.tmp.name, "history": True})
            self.assertEqual(status, 400)
            self.assertIn("repositório git", json.loads(texto)["error"])
        self.assertNotIn("Traceback", texto)


@unittest.skipUnless(GIT, "git não instalado")
class Demonstracao(GuiBase):
    def test_pasta_demo_mostra_varias_regras_e_um_segredo_ja_apagado(self):
        demo_dir = tempfile.mkdtemp(prefix="secretscan-demo-test-")
        self.addCleanup(demo.apagar, demo_dir)
        self.assertTrue(demo.criar(demo_dir))
        status, _, texto = self.req("POST", "/api/scan", {"path": demo_dir, "history": True})
        self.assertEqual(status, 200)
        achados = json.loads(texto)["report"]["findings"]
        regras = {f["rule"] for f in achados}
        for esperado in ("aws-access-key-id", "stripe-live-key", "private-key", "url-credentials",
                         "password-assignment", "cpf", "cnpj", "github-token"):
            self.assertIn(esperado, regras)
        apagados = [f for f in achados if f.get("removed_from_code")]
        self.assertEqual([f["rule"] for f in apagados], ["github-token"])
        for f in achados:
            self.assertTrue(f["masked"])

    def test_demo_nao_deixa_o_projeto_se_acusar(self):
        # os valores da demo são montados em partes: o código-fonte do projeto continua limpo
        from secretscan.scanner import scan_path
        raiz = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.assertEqual(scan_path(raiz).findings, [])


if __name__ == "__main__":
    unittest.main()
