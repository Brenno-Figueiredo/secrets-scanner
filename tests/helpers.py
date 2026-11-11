"""Segredos de teste montados em tempo de execução: o código-fonte dos testes nunca contém um
segredo por extenso (senão o scanner acusaria o próprio projeto)."""
import random

_ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def rnd(n, alfabeto=_ALNUM, seed=7):
    r = random.Random(seed)
    return "".join(r.choice(alfabeto) for _ in range(n))


def cpf(base="123456789"):
    """CPF válido calculado de forma independente do validador do projeto."""
    d = [int(c) for c in base]
    for n in (9, 10):
        s = sum(v * w for v, w in zip(d, range(n + 1, 1, -1)))
        d.append((s * 10 % 11) % 10)
    t = "".join(map(str, d))
    return t[:3] + "." + t[3:6] + "." + t[6:9] + "-" + t[9:]


def cnpj(base12):
    """CNPJ válido, calculado com outra formulação (tabela de pesos única, módulo explícito)."""
    d = [int(c) for c in base12]
    pesos = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    for n in (12, 13):
        resto = sum(v * p for v, p in zip(d, pesos[len(pesos) - n:])) % 11
        d.append(0 if resto < 2 else 11 - resto)
    t = "".join(map(str, d))
    return f"{t[:2]}.{t[2:5]}.{t[5:8]}/{t[8:12]}-{t[12:]}"


def amostras():
    """Uma linha de código com um segredo para cada uma das 23 regras."""
    return {
        "aws-access-key-id": "chave = '" + "AKIA" + rnd(16, _UPPER) + "'",
        "aws-secret-access-key": "aws_secret_access_key = " + rnd(40, seed=3),
        "github-token": "token_gh = " + "gh" + "p_" + rnd(36, seed=4),
        "github-fine-grained-pat": "x = " + "github" + "_pat_" + rnd(40, seed=5),
        "gitlab-pat": "x = " + "glp" + "at-" + rnd(20, seed=6),
        "slack-token": "x = " + "xox" + "b-" + rnd(24, seed=8),
        "slack-webhook": "hook = https://hooks." + "slack.com/services/T" + rnd(9, _UPPER, 1) + "/B"
                         + rnd(9, _UPPER, 2) + "/" + rnd(24, seed=9),
        "google-api-key": "k = " + "AI" + "za" + rnd(35, seed=10),
        "stripe-live-key": "k = " + "sk" + "_live_" + rnd(30, seed=11),
        "twilio-api-key": "k = " + "S" + "K" + rnd(32, "0123456789abcdef", 12),
        "sendgrid-api-key": "k = " + "S" + "G." + rnd(22, seed=13) + "." + rnd(43, seed=14),
        "openai-api-key": "k = " + "sk" + "-" + rnd(48, seed=15),
        "anthropic-api-key": "k = " + "sk" + "-ant-" + rnd(60, seed=16),
        "npm-token": "k = " + "npm" + "_" + rnd(36, seed=17),
        "private-key": "-----" + "BEGIN " + "RSA PRIVATE KEY-----",
        "jwt": "t = " + "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + rnd(30, seed=18),
        "url-credentials": "u = 'postgres://app:" + rnd(12, seed=19) + "@db.interno:5432/prod'",
        "password-assignment": "senha = '" + rnd(12, seed=20) + "'",
        "high-entropy-secret": "auth_value: '" + rnd(40, seed=21) + "'",
        "azure-storage-key": "Account" + "Key=" + rnd(64, seed=22) + "==",
        "telegram-bot-token": "bot = " + "1234567890" + ":AA" + rnd(33, seed=23),
        "cpf": "documento = '" + cpf() + "'",
        "cnpj": "empresa = '" + cnpj("112223330001") + "'",
    }
