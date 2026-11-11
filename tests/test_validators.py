import random
import unittest

from secretscan.validators import cnpj_valido, cpf_valido, entropia
from tests.helpers import cnpj, cpf


class CpfTests(unittest.TestCase):
    def test_valido_e_formatos(self):
        c = cpf()
        self.assertTrue(cpf_valido(c))
        self.assertTrue(cpf_valido(c.replace(".", "").replace("-", "")))

    def test_digito_errado(self):
        c = cpf()
        ruim = c[:-1] + str((int(c[-1]) + 1) % 10)
        self.assertFalse(cpf_valido(ruim))

    def test_repetidos_e_tamanho(self):
        self.assertFalse(cpf_valido("111.111.111-11"))
        self.assertFalse(cpf_valido("123"))

    def test_muitos_cpfs_gerados(self):
        r = random.Random(1)
        for _ in range(1500):
            base = "".join(r.choice("0123456789") for _ in range(9))
            if len(set(base)) == 1:
                continue
            self.assertTrue(cpf_valido(cpf(base)), base)


class CnpjTests(unittest.TestCase):
    def test_1500_cnpjs_gerados_de_forma_independente(self):
        r = random.Random(2)
        zeros = 0
        for _ in range(1500):
            base = "".join(r.choice("0123456789") for _ in range(12))
            if len(set(base)) == 1:
                continue
            c = cnpj(base)
            zeros += c.endswith("0-00") or c[-2] == "0" or c[-1] == "0"
            self.assertTrue(cnpj_valido(c), c)
        self.assertGreater(zeros, 50, "o conjunto precisa incluir dígitos verificadores 0")

    def test_digito_errado_sempre_rejeitado(self):
        r = random.Random(3)
        for _ in range(500):
            base = "".join(r.choice("0123456789") for _ in range(12))
            if len(set(base)) == 1:
                continue
            c = cnpj(base)
            ruim = c[:-1] + str((int(c[-1]) + 1) % 10)
            self.assertFalse(cnpj_valido(ruim), ruim)

    def test_repetidos(self):
        self.assertFalse(cnpj_valido("00.000.000/0000-00"))


class EntropiaTests(unittest.TestCase):
    def test_extremos(self):
        self.assertEqual(entropia(""), 0.0)
        self.assertEqual(entropia("aaaa"), 0.0)
        self.assertAlmostEqual(entropia("abcd"), 2.0)


if __name__ == "__main__":
    unittest.main()
