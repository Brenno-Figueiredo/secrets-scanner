"""As 23 regras de detecção.

Cada regra tem uma ou mais expressões regulares (com o grupo que contém o segredo) e, opcionalmente,
um validador que descarta falsos positivos (placeholder, CPF com dígito errado, entropia baixa...).

Todas as expressões usam quantificadores LIMITADOS ({n,m}) para não serem alvo de backtracking
catastrófico (ReDoS); os testes as exercitam com entradas feitas para travá-las.
Ordem importa: regras específicas vêm antes das genéricas, e um trecho já reivindicado não é
reportado duas vezes.
"""
import base64
import binascii
import json
import re

from .validators import cnpj_valido, cpf_valido, entropia

_EXATOS = {
    "password", "passwd", "pass", "senha", "secret", "token", "apikey", "api_key", "changeme",
    "null", "none", "nil", "true", "false", "undefined", "string", "redacted", "username", "user",
}
_PARTES = (
    "example", "exemplo", "changeme", "change_me", "change-me", "your", "seu_", "sua_", "xxxx", "****",
    "....", "<", ">", "${", "{{", "%s", "%(", "{}", "dummy", "placeholder", "todo", "fixme",
    "process.env", "os.environ", "getenv", "env[", "secret_here", "insert", "coloque", "preencha",
)
_ESQUEMA = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
_IPV4 = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?")


def eh_placeholder(valor):
    v = valor.lower()
    if v in _EXATOS or len(set(v)) <= 2:
        return True
    if v[0] in "$%{":
        return True
    return any(p in v for p in _PARTES)


_VERSAO = re.compile(r"[\^~<>=v ]*\d+(?:\.[\dxX*]+)*(?:[-+][\w.]+)?")
_IDENTIFICADOR = re.compile(r"[a-z]+(?:[_\-][a-z]+)+")  # brute_force, auth-failure: nome, não senha
_FORTES = ("password", "passwd", "pwd", "senha")


def _senha_ok(valor, linha, m):
    if eh_placeholder(valor):
        return False
    if _ESQUEMA.match(valor) or _IPV4.fullmatch(valor):  # endereço guardado numa variável "senha"
        return False
    if _VERSAO.fullmatch(valor) or _IDENTIFICADOR.fullmatch(valor):  # "^3.0.0", "brute_force"
        return False
    if valor.count(":") >= 3 or "\\n" in valor:  # conteúdo de /etc/passwd ou /etc/shadow
        return False
    if valor.startswith("__") and valor.endswith("__"):
        return False
    chave = m.group(0)[: m.start(1) - m.start(0)].lower()
    if not any(k in chave for k in _FORTES):
        # secret/token/api_key: só vale se o valor parece gerado (dígito ou maiúscula + minúscula)
        misto = any(c.isupper() for c in valor) and any(c.islower() for c in valor)
        return misto or any(c.isdigit() for c in valor)
    return True


def _url_ok(valor, linha, m):
    return not eh_placeholder(valor)


def _entropia_ok(valor, linha, m):
    if eh_placeholder(valor):
        return False
    if not (any(c.isdigit() for c in valor) and any(c.isalpha() for c in valor)):
        return False
    return entropia(valor) >= 3.5


def _aws_secret_ok(valor, linha, m):
    return not eh_placeholder(valor) and entropia(valor) >= 3.5


def _jwt_ok(valor, linha, m):
    try:
        cab = valor.split(".")[0]
        bruto = base64.urlsafe_b64decode(cab + "=" * (-len(cab) % 4))
        return isinstance(json.loads(bruto), dict)
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return False


def _cpf_ok(valor, linha, m):
    if not cpf_valido(valor):
        return False
    return valor.isdigit() is False or "cpf" in linha.lower()


def _cnpj_ok(valor, linha, m):
    if not cnpj_valido(valor):
        return False
    return valor.isdigit() is False or "cnpj" in linha.lower()


class Rule:
    __slots__ = ("id", "title", "severity", "patterns", "validate")

    def __init__(self, id, title, severity, patterns, validate=None):
        self.id = id
        self.title = title
        self.severity = severity
        self.patterns = [(re.compile(p), g) for p, g in patterns]
        self.validate = validate


_CH = r"[A-Za-z0-9_\-]"
_FIM = r"(?![A-Za-z0-9_\-])"

RULES = [
    Rule("aws-access-key-id", "Chave de acesso da AWS", "critical",
         [(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z0-9]{16}\b", 0)]),
    Rule("aws-secret-access-key", "Chave secreta da AWS", "critical",
         [(r"(?i:aws[_\-]?secret[_\-]?(?:access[_\-]?)?key)[\w.\-]{0,10}[\"']?\s{0,3}[:=]{1,2}\s{0,3}[\"']?"
           r"([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])", 1)], _aws_secret_ok),
    Rule("github-token", "Token do GitHub", "critical",
         [(r"\bgh[pousr]_[A-Za-z0-9]{36,255}(?![A-Za-z0-9])", 0)]),
    Rule("github-fine-grained-pat", "Token granular do GitHub", "critical",
         [(r"\bgithub_pat_[A-Za-z0-9_]{22,255}(?![A-Za-z0-9_])", 0)]),
    Rule("gitlab-pat", "Token pessoal do GitLab", "critical",
         [(r"\bglpat-" + _CH + r"{20}" + _FIM, 0)]),
    Rule("slack-token", "Token do Slack", "critical",
         [(r"\bxox[abposr]-[A-Za-z0-9\-]{10,120}", 0)]),
    Rule("slack-webhook", "Webhook do Slack", "high",
         [(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}", 0)]),
    Rule("google-api-key", "Chave de API do Google", "high",
         [(r"\bAIza[0-9A-Za-z_\-]{35}" + _FIM, 0)]),
    Rule("stripe-live-key", "Chave secreta do Stripe (produção)", "critical",
         [(r"\b[sr]k_live_[0-9A-Za-z]{24,99}(?![0-9A-Za-z])", 0)]),
    Rule("twilio-api-key", "Chave de API do Twilio", "high",
         [(r"\bSK[0-9a-fA-F]{32}\b", 0)]),
    Rule("sendgrid-api-key", "Chave de API do SendGrid", "critical",
         [(r"\bSG\." + _CH + r"{22}\." + _CH + r"{43}" + _FIM, 0)]),
    Rule("openai-api-key", "Chave de API da OpenAI", "critical",
         [(r"\bsk-(?!ant-)(?:proj-|svcacct-)?" + _CH + r"{32,200}" + _FIM, 0)]),
    Rule("anthropic-api-key", "Chave de API da Anthropic", "critical",
         [(r"\bsk-ant-" + _CH + r"{40,200}" + _FIM, 0)]),
    Rule("npm-token", "Token do npm", "critical",
         [(r"\bnpm_[A-Za-z0-9]{36}(?![A-Za-z0-9])", 0)]),
    Rule("private-key", "Chave privada (cabeçalho PEM)", "critical",
         [(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----", 0)]),
    Rule("jwt", "JSON Web Token", "medium",
         [(r"\beyJ[A-Za-z0-9_\-]{8,200}\.eyJ[A-Za-z0-9_\-]{8,1000}\.[A-Za-z0-9_\-]{8,600}", 0)], _jwt_ok),
    Rule("url-credentials", "Senha dentro de uma URL", "high",
         [(r"\b[A-Za-z][A-Za-z0-9+.\-]{1,15}://([^\s:/@'\"<>{}$%]{1,64}):([^\s:/@'\"<>{}$%]{3,64})"
           r"@[^\s/'\"<>]{1,128}", 2)], _url_ok),
    Rule("password-assignment", "Senha ou segredo escrito no código", "high",
         [(r"(?<![/@])(?i:password|passwd|pwd|senha|secret|api[_\-]?key|apikey|token)[\w.\-]{0,20}[\"']?\s{0,3}"
           r"[:=]{1,2}\s{0,3}[\"']([^\"'\s]{6,128})[\"']", 1),
          (r"(?m)^[ \t]*(?:export[ \t]+)?[A-Z][A-Z0-9_]{0,40}(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|SENHA)"
           r"[A-Z0-9_]{0,20}[ \t]*=[ \t]*([^\s\"'#$]{6,128})[ \t]*$", 1)], _senha_ok),
    Rule("high-entropy-secret", "Valor aleatório em variável de segredo", "medium",
         [(r"(?i:secret|token|api[_\-]?key|apikey|auth|credential|private[_\-]?key)[\w.\-]{0,20}[\"']?\s{0,3}"
           r"[:=]{1,2}\s{0,3}[\"']([A-Za-z0-9+/=_\-]{24,128})[\"']", 1)], _entropia_ok),
    Rule("azure-storage-key", "Chave de conta de armazenamento do Azure", "critical",
         [(r"AccountKey=([A-Za-z0-9+/=]{60,100})", 1)]),
    Rule("telegram-bot-token", "Token de bot do Telegram", "high",
         [(r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}(?![A-Za-z0-9_\-])", 0)]),
    Rule("cpf", "CPF válido (LGPD)", "medium",
         [(r"(?<![\d.\-/])\d{3}\.\d{3}\.\d{3}-\d{2}(?![\d\-])", 0),
          (r"(?<![\d.\-/])\d{11}(?![\d])", 0)], _cpf_ok),
    Rule("cnpj", "CNPJ válido (LGPD)", "medium",
         [(r"(?<![\d.\-/])\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}(?![\d\-])", 0),
          (r"(?<![\d.\-/])\d{14}(?![\d])", 0)], _cnpj_ok),
]

assert len(RULES) == 23 and len({r.id for r in RULES}) == 23
