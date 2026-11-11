import time
import unittest

from secretscan.rules import RULES, eh_placeholder
from secretscan.scanner import scan_line, scan_text
from tests.helpers import amostras, cnpj, cpf, rnd


def ids(linha):
    return [f.rule_id for f in scan_line(linha, 1, "x.py")]


class CoberturaDasRegras(unittest.TestCase):
    def test_existem_23_regras_unicas(self):
        self.assertEqual(len(RULES), 23)
        self.assertEqual(len({r.id for r in RULES}), 23)

    def test_toda_regra_tem_amostra_e_detecta(self):
        am = amostras()
        self.assertEqual(set(am), {r.id for r in RULES})
        for rid, linha in am.items():
            self.assertIn(rid, ids(linha), f"{rid} não detectou: {linha[:40]}")

    def test_o_segredo_bruto_nao_vai_para_o_snippet(self):
        for rid, linha in amostras().items():
            for f in scan_line(linha, 1, "x.py"):
                if f.rule_id == "private-key":
                    continue
                self.assertNotIn(f.secret, f.snippet, rid)
                self.assertNotIn(f.secret, f.masked, rid)


class FalsosPositivos(unittest.TestCase):
    def test_conteudo_de_etc_passwd_nao_e_senha(self):
        texto = ("root:x:0:0:root:/root:/bin/bash\n"
                 "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                 "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
                 "app:$6$salt$hash:19000:0:99999:7:::\n")
        self.assertEqual(scan_text(texto), [])

    def test_fstring_e_variaveis_nao_acusam(self):
        for linha in ['u = f"postgres://u:{senha}@host/db"', 'u = "postgres://u:${PASS}@host/db"',
                      'u = "mysql://root:%s@localhost"', 'senha = os.environ["SENHA"]',
                      'password = "${DB_PASSWORD}"', 'password = "<sua-senha-aqui>"',
                      'password = "changeme"', 'token = "xxxxxxxxxxxx"',
                      'api_key = "your_api_key_here"', "DB_PASSWORD=${DB_PASSWORD}",
                      "u = 'postgres://user:password@localhost/db'"]:
            self.assertEqual(ids(linha), [], linha)

    def test_endereco_atribuido_a_variavel_de_senha(self):
        self.assertEqual(ids('password_url = "http://exemplo.interno/painel"'), [])
        self.assertEqual(ids('senha_host = "192.168.0.10"'), [])

    def test_cpf_cnpj_invalidos_ou_dentro_de_numero_maior(self):
        c = cpf()
        ruim = c[:-1] + str((int(c[-1]) + 1) % 10)
        self.assertEqual(ids(f"x = '{ruim}'"), [])
        self.assertEqual(ids("id = 1234567890123456789"), [])
        self.assertEqual(ids(f"versao 1.{c}.2"), [])
        self.assertEqual(ids("pedido 12345678909"), [])  # 11 dígitos, sem a palavra-chave

    def test_cpf_sem_pontuacao_so_com_palavra_cpf(self):
        puro = cpf().replace(".", "").replace("-", "")
        self.assertEqual(ids(f"pedido {puro}"), [])
        self.assertEqual(ids(f"cpf: {puro}"), ["cpf"])

    def test_jwt_falso_nao_acusa(self):
        self.assertEqual(ids("t = eyJ" + "a" * 20 + ".eyJ" + "b" * 20 + "." + "c" * 20), [])

    def test_ignorar_na_linha(self):
        self.assertEqual(ids(amostras()["aws-access-key-id"] + "  # secretscan:ignore"), [])

    def test_placeholders(self):
        for v in ("changeme", "<senha>", "${X}", "aaaaaa", "exemplo123"):
            self.assertTrue(eh_placeholder(v), v)
        self.assertFalse(eh_placeholder(rnd(12)))


class VariasCoisas(unittest.TestCase):
    def test_json_com_aspas_na_chave(self):
        self.assertIn("password-assignment", ids('{"password": "' + rnd(12) + '"}'))

    def test_env_maiusculo_sem_aspas(self):
        self.assertIn("password-assignment", ids("DB_PASSWORD=" + rnd(14)))

    def test_cnpj_valido(self):
        self.assertEqual(ids("empresa " + cnpj("123456780001")), ["cnpj"])

    def test_dois_segredos_na_mesma_linha_ficam_mascarados_no_snippet(self):
        a, b = amostras()["aws-access-key-id"], amostras()["github-token"]
        achados = scan_line(a + " ; " + b, 1, "x.py")
        self.assertGreaterEqual(len(achados), 2)
        for f in achados:
            for outro in achados:
                self.assertNotIn(outro.secret, f.snippet)

    def test_linha_gigante_com_segredo_no_fim(self):
        linha = "x" * 20000 + " " + amostras()["aws-access-key-id"]
        self.assertIn("aws-access-key-id", ids(linha))

    def test_segredo_encostado_na_juncao_das_janelas(self):
        for posicao in (3790, 3800, 3900, 7600):
            linha = " " * posicao + amostras()["github-token"]
            self.assertIn("github-token", ids(linha), posicao)


class ReDoS(unittest.TestCase):
    """Cada regra contra entradas feitas para provocar backtracking: tem de responder rápido."""

    ENTRADAS = [
        "a" * 100000, "0" * 100000, "AKIA" * 25000, "eyJ" * 30000, "eyJ" + "a" * 100000,
        "-----BEGIN " * 10000, "password" + " " * 100000, "password" + "=" * 100000,
        "password=\"" + "a" * 100000, "http://" + "a:" * 50000, "http://a:" + "b" * 100000,
        "secret" + "_" * 100000, "token='" + "A" * 100000, "0." * 50000, "1.1.1-" * 20000,
        "AccountKey=" + "A" * 100000, "SG." + "a" * 100000, "xoxb-" + "-" * 100000,
        "123456789:AA" + "a" * 100000, "AWS_SECRET_KEY" + "a" * 100000, "export " * 20000,
        "Z_" * 50000 + "=", "\t" * 100000 + "TOKEN=", "://" * 30000, "@" * 100000,
    ]

    def test_nenhuma_entrada_trava(self):
        pior = 0.0
        for entrada in self.ENTRADAS:
            t = time.perf_counter()
            scan_line(entrada, 1, "x")
            dt = time.perf_counter() - t
            pior = max(pior, dt)
            self.assertLess(dt, 3.0, f"lento ({dt:.2f}s) com {entrada[:20]!r}...")
        self.assertLess(pior, 3.0)


if __name__ == "__main__":
    unittest.main()


class FalsosPositivosDeDados(unittest.TestCase):
    """Casos reais que o scanner acusou por engano ao rodar nos projetos do autor."""

    def test_versoes_do_package_lock(self):
        for linha in ['"@csstools/css-tokenizer": "^3.0.0",', '"js-tokens": "^4.0.0"',
                      '"@inquirer/password": "^6.0.0",', '"token-types": "~1.2.3"']:
            self.assertEqual(ids(linha), [], linha)

    def test_etc_passwd_dentro_de_json_ou_codigo(self):
        self.assertEqual(ids('"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\\n",'), [])
        self.assertEqual(ids('passwd = "root:x:0:0:root:/root:/bin/sh\\n" + extra'), [])

    def test_nomes_de_regra_e_rotas_nao_sao_senha(self):
        self.assertEqual(ids('{"password_spraying": "brute_force", "x": "auth_failure"}'), [])
        self.assertEqual(ids('{"/api/user/password": "viewer"}'), [])
        self.assertEqual(ids('TOKEN_PLACEHOLDER = "__MEU_TOKEN__"'), [])

    def test_token_curto_e_so_letras_nao_acusa_mas_senha_sim(self):
        self.assertEqual(ids("token = 'abcdefgh'"), [])
        self.assertIn("password-assignment", ids("pass" + "word = 'abcdefgh'"))
