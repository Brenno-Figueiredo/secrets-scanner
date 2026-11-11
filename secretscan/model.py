"""Modelo de dados e mascaramento. Nenhum relatório pode mostrar um segredo inteiro."""
import hashlib
from dataclasses import dataclass, field
from typing import Optional

SEVERIDADES = ("low", "medium", "high", "critical")


def sev_rank(sev):
    return SEVERIDADES.index(sev)


def mask_secret(rule_id, secret):
    """Versão mascarada: nunca devolve o segredo inteiro."""
    n = len(secret)
    if rule_id == "private-key":  # o que casa é só o cabeçalho PEM, não a chave: mostrá-lo não expõe nada
        return secret
    if rule_id in ("cpf", "cnpj"):
        return "".join("*" if c.isdigit() else c for c in secret[:-2]) + secret[-2:]
    if n <= 8:
        return "*" * n
    if n <= 12:
        return secret[:1] + "*" * (n - 2) + secret[-1:]
    return secret[:2] + "*" * min(n - 4, 12) + secret[-2:]


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    masked: str
    snippet: str
    commit: Optional[str] = None
    author: Optional[str] = None
    date: Optional[str] = None
    removed: Optional[bool] = None  # True: já saiu do código, mas continua no histórico
    # O segredo bruto só existe em memória: fica fora de repr, de comparação e de qualquer relatório.
    secret: str = field(default="", repr=False, compare=False)

    def chave(self):
        """Identidade do segredo (regra + valor), só para deduplicar em memória."""
        return hashlib.sha256((self.rule_id + "\0" + self.secret).encode("utf-8", "replace")).hexdigest()

    def to_dict(self):
        d = {
            "rule": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "masked": self.masked,
            "snippet": self.snippet,
        }
        if self.commit:
            d.update({"commit": self.commit, "author": self.author, "date": self.date,
                      "removed_from_code": bool(self.removed)})
        return d
