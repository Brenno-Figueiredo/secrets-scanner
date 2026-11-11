"""Validadores usados pelas regras: CPF, CNPJ (dígitos verificadores) e entropia de Shannon."""
import math
from collections import Counter


def _digitos(texto):
    return [int(c) for c in texto if c.isdigit()]


def cpf_valido(texto):
    """True se o texto tem 11 dígitos e os dois dígitos verificadores batem."""
    d = _digitos(texto)
    if len(d) != 11 or len(set(d)) == 1:
        return False
    for n in (9, 10):
        soma = sum(d[i] * (n + 1 - i) for i in range(n))
        dv = (soma * 10) % 11
        if dv == 10:
            dv = 0
        if dv != d[n]:
            return False
    return True


_PESOS_CNPJ = (
    (12, (5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)),
    (13, (6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)),
)


def cnpj_valido(texto):
    """True se o texto tem 14 dígitos e os dois dígitos verificadores batem."""
    d = _digitos(texto)
    if len(d) != 14 or len(set(d)) == 1:
        return False
    for n, pesos in _PESOS_CNPJ:
        resto = sum(a * b for a, b in zip(d[:n], pesos)) % 11
        # if/else explícito: o truque "x and 0 or y" erra quando o dígito é 0
        if resto < 2:
            dv = 0
        else:
            dv = 11 - resto
        if dv != d[n]:
            return False
    return True


def entropia(texto):
    """Entropia de Shannon, em bits por caractere."""
    if not texto:
        return 0.0
    total = len(texto)
    return -sum((c / total) * math.log2(c / total) for c in Counter(texto).values())
