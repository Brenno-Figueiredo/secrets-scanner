"""Interface gráfica local: uma página no navegador, servida só em 127.0.0.1 (nada sai do seu computador).

Proteções: escuta apenas em localhost; confere o cabeçalho Host (contra DNS rebinding) e o Origin;
toda ação exige um token aleatório gerado a cada execução; corpo limitado; nunca devolve o segredo
inteiro (só os campos já mascarados dos relatórios); erros não mostram detalhes internos.
"""
import hmac
import json
import os
import secrets
import subprocess
import sys
import tempfile
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__, demo, report
from .scanner import ScanResult, SecretscanError, is_git_repo, scan_history, scan_path

PAGINA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "index.html")
MAX_CORPO = 64 * 1024
CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; "
       "img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def executar_varredura(caminho, historico, excludes=()):
    caminho = os.path.abspath(os.path.expanduser(str(caminho).strip().strip('"')))
    if not os.path.isdir(caminho):
        raise SecretscanError(f"pasta não encontrada: {caminho}")
    result = scan_path(caminho, excludes)
    findings = result.findings
    if historico:
        if not is_git_repo(caminho):
            raise SecretscanError("esta pasta não é um repositório git: desmarque \"histórico do git\"")
        findings = scan_history(caminho, findings, None, excludes)
    return {"path": caminho, "report": report.to_dict(findings, result),
            "sarif": report.render_sarif(findings), "venator": report.render_venator(findings)}


def escolher_pasta():
    """Abre a janela de escolher pasta do sistema (tkinter, num processo à parte). Vazio se não der."""
    codigo = ("import tkinter as tk\nfrom tkinter import filedialog\nr = tk.Tk()\nr.withdraw()\n"
              "r.attributes('-topmost', True)\n"
              "print(filedialog.askdirectory(title='Escolha a pasta para varrer') or '')\n")
    try:
        saida = subprocess.run([sys.executable, "-c", codigo], capture_output=True, text=True, encoding="utf-8",
                               timeout=300, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return saida.stdout.strip() if saida.returncode == 0 else ""


class _Handler(BaseHTTPRequestHandler):
    server_version = "secretscan"

    def log_message(self, *args):  # silencioso: nada de caminhos no terminal
        pass

    def _responder(self, codigo, corpo, tipo):
        dados = corpo if isinstance(corpo, bytes) else corpo.encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(dados)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(dados)

    def _json(self, codigo, obj):
        self._responder(codigo, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")

    def _origem_ok(self):
        if self.headers.get("Host", "") not in self.server.hosts_ok:
            return False
        origem = self.headers.get("Origin")
        return origem is None or origem in self.server.origens_ok

    def do_GET(self):
        if not self._origem_ok():
            return self._json(403, {"error": "acesso negado"})
        if self.path.split("?", 1)[0] != "/":
            return self._json(404, {"error": "não encontrado"})
        with open(PAGINA, encoding="utf-8") as f:
            html = f.read()
        config = json.dumps({"token": self.server.token, "path": self.server.pasta_padrao,
                             "demo": self.server.demo, "version": __version__}).replace("<", "\\u003c")
        self._responder(200, html.replace("__CONFIG__", config), "text/html; charset=utf-8")

    def do_POST(self):
        if not self._origem_ok():
            return self._json(403, {"error": "acesso negado"})
        if not hmac.compare_digest(self.headers.get("X-Token", ""), self.server.token):
            return self._json(403, {"error": "token inválido: recarregue a página"})
        try:
            tam = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            tam = -1
        if tam < 0 or tam > MAX_CORPO:
            return self._json(413, {"error": "pedido grande demais"})
        try:
            corpo = json.loads(self.rfile.read(tam) or b"{}")
            if not isinstance(corpo, dict):
                raise ValueError
        except ValueError:
            return self._json(400, {"error": "JSON inválido"})
        rota = self.path.split("?", 1)[0]
        if rota == "/api/pick":
            return self._json(200, {"path": escolher_pasta()})
        if rota == "/api/scan":
            excl = corpo.get("exclude", [])
            if not isinstance(excl, list) or not all(isinstance(e, str) for e in excl):
                return self._json(400, {"error": "campo exclude inválido"})
            try:
                return self._json(200, executar_varredura(corpo.get("path", ""), bool(corpo.get("history")), excl))
            except SecretscanError as e:
                return self._json(400, {"error": str(e)})
            except OSError:
                return self._json(400, {"error": "não foi possível ler essa pasta"})
        return self._json(404, {"error": "não encontrado"})


def make_server(port=8765, pasta_padrao=".", demo_mode=False):
    """Cria o servidor em 127.0.0.1. Com porta ocupada, tenta as 20 seguintes (porta 0 = qualquer livre)."""
    ultimo = None
    for p in ([0] if port == 0 else range(port, port + 20)):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", p), _Handler)
            break
        except OSError as e:
            ultimo = e
    else:
        raise SecretscanError(f"não consegui abrir uma porta perto de {port}: {ultimo}")
    porta = srv.server_address[1]
    srv.token = secrets.token_urlsafe(32)
    srv.hosts_ok = {f"127.0.0.1:{porta}", f"localhost:{porta}"}
    srv.origens_ok = {f"http://127.0.0.1:{porta}", f"http://localhost:{porta}"}
    srv.pasta_padrao = os.path.abspath(pasta_padrao)
    srv.demo = demo_mode
    return srv


def serve(port=8765, pasta=".", demo_mode=False, abrir=True):
    tmp = None
    if demo_mode:
        tmp = tempfile.mkdtemp(prefix="secretscan-demo-")
        demo.criar(tmp)
        pasta = tmp
    try:
        srv = make_server(port, pasta, demo_mode)
        url = f"http://127.0.0.1:{srv.server_address[1]}/"
        print(f"secrets-scanner: interface em {url}")
        print("Dados de demonstração (falsos)." if demo_mode else "Tudo roda no seu computador.")
        print("Pressione Ctrl+C para encerrar.")
        if abrir:
            threading.Timer(0.5, webbrowser.open, args=(url,)).start()
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nencerrado.")
        finally:
            srv.server_close()
    finally:
        if tmp:
            demo.apagar(tmp)
    return 0
