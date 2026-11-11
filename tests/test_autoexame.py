import os
import unittest

from secretscan.scanner import scan_path

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Autoexame(unittest.TestCase):
    def test_o_projeto_nao_acusa_a_si_mesmo(self):
        achados = scan_path(RAIZ).findings
        self.assertEqual([(f.rule_id, f.file, f.line) for f in achados], [])


if __name__ == "__main__":
    unittest.main()
