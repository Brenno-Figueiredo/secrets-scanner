"""Linha de comando."""
import argparse
import os
import sys

from . import __version__, baseline, hook, report
from .model import SEVERIDADES, sev_rank
from .rules import RULES
from .scanner import ScanResult, SecretscanError, is_git_repo, scan_history, scan_path, scan_staged

APP_PY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")


def _utf8():
    for fluxo in (sys.stdout, sys.stderr):
        try:
            fluxo.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def _renderizar(args, findings, result, suprimidos):
    if args.format == "json":
        return report.render_json(findings, result, suprimidos)
    if args.format == "sarif":
        return report.render_sarif(findings)
    if args.format == "venator":
        return report.render_venator(findings)
    cor = sys.stdout.isatty() and not args.no_color and not args.output and "NO_COLOR" not in os.environ
    return report.render_text(findings, result, suprimidos, cor)


def _saida(args, texto, findings):
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as f:
            f.write(texto)
        print(f"relatório salvo em {args.output} ({len(findings)} achado(s))", file=sys.stderr)
    else:
        sys.stdout.write(texto)


def _codigo(findings, fail_on):
    limite = sev_rank(fail_on)
    return 1 if any(sev_rank(f.severity) >= limite for f in findings) else 0


def cmd_scan(args):
    paths = args.paths or ["."]
    result = ScanResult()
    for p in paths:
        result.merge(scan_path(p, args.exclude))
    findings = result.findings
    if args.history:
        if len(paths) != 1 or not os.path.isdir(paths[0]) or not is_git_repo(paths[0]):
            raise SecretscanError("--history exige exatamente uma pasta que seja um repositório git")
        findings = scan_history(paths[0], findings, args.max_commits, args.exclude)
    suprimidos = 0
    if args.baseline:
        findings, suprimidos = baseline.filtrar(findings, args.baseline)
    _saida(args, _renderizar(args, findings, result, suprimidos), findings)
    return _codigo(findings, args.fail_on)


def cmd_scan_staged(args):
    findings = scan_staged(".", args.exclude)
    base = baseline.BASELINE_PADRAO
    if os.path.exists(base):
        findings, _ = baseline.filtrar(findings, base)
    if not findings:
        return 0
    sys.stderr.write(report.render_text(findings))
    sys.stderr.write("\nCommit recusado: há segredo ou dado pessoal no que você está commitando.\n"
                     "  - Remova o valor (e troque a credencial, se ela for real).\n"
                     f"  - Falso positivo? Acrescente `{'secretscan:ignore'}` num comentário da linha, "
                     "ou registre na linha de base: python app.py baseline\n"
                     "  - Para pular a verificação uma vez: git commit --no-verify\n")
    return _codigo(findings, args.fail_on) if args.fail_on else 1


def cmd_baseline(args):
    result = scan_path(args.path, args.exclude)
    findings = result.findings
    if args.history:
        findings = scan_history(args.path, findings, None, args.exclude)
    n = baseline.criar(findings, args.output)
    print(f"linha de base com {n} achado(s) salva em {args.output}")
    print("O arquivo guarda só impressões digitais (HMAC); a chave fica fora do commit.")
    return 0


def cmd_install_hook(args):
    destino = hook.instalar(args.repo, APP_PY, args.force)
    print(f"hook instalado em {destino}")
    return 0


def cmd_uninstall_hook(args):
    destino = hook.remover(args.repo)
    print(f"hook removido: {destino}" if destino else "nenhum hook instalado")
    return 0


def cmd_rules(args):
    for r in RULES:
        print(f"{r.id:26} {r.severity:9} {r.title}")
    print(f"\n{len(RULES)} regras")
    return 0


def construir_parser():
    p = argparse.ArgumentParser(prog="secrets-scanner", description="Detector de segredos e dados "
                                "pessoais (CPF/CNPJ) em código e no histórico do git.")
    p.add_argument("--version", action="version", version=f"secrets-scanner {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="varre arquivos/pastas (e, com --history, o histórico do git)")
    s.add_argument("paths", nargs="*", help="arquivos ou pastas (padrão: pasta atual)")
    s.add_argument("--history", action="store_true", help="varre também todos os commits")
    s.add_argument("--max-commits", type=int, help="limita o histórico aos N commits mais recentes")
    s.add_argument("--format", choices=report.FORMATOS, default="text")
    s.add_argument("-o", "--output", help="salva o relatório neste arquivo")
    s.add_argument("--baseline", help="linha de base com achados conhecidos a ignorar")
    s.add_argument("--fail-on", choices=SEVERIDADES, default="medium",
                   help="severidade mínima que faz o comando sair com código 1 (padrão: medium)")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="ignora arquivos (repetível)")
    s.add_argument("--no-color", action="store_true")
    s.set_defaults(func=cmd_scan)

    st = sub.add_parser("scan-staged", help="varre o que está no index (usado pelo hook)")
    st.add_argument("--fail-on", choices=SEVERIDADES, default=None)
    st.add_argument("--exclude", action="append", default=[], metavar="GLOB")
    st.set_defaults(func=cmd_scan_staged)

    b = sub.add_parser("baseline", help="registra os achados atuais como conhecidos")
    b.add_argument("path", nargs="?", default=".")
    b.add_argument("-o", "--output", default=baseline.BASELINE_PADRAO)
    b.add_argument("--history", action="store_true")
    b.add_argument("--exclude", action="append", default=[], metavar="GLOB")
    b.set_defaults(func=cmd_baseline)

    i = sub.add_parser("install-hook", help="instala o hook de pre-commit num repositório")
    i.add_argument("--repo", default=".")
    i.add_argument("--force", action="store_true")
    i.set_defaults(func=cmd_install_hook)

    u = sub.add_parser("uninstall-hook", help="remove o hook deste projeto")
    u.add_argument("--repo", default=".")
    u.set_defaults(func=cmd_uninstall_hook)

    r = sub.add_parser("rules", help="lista as regras")
    r.set_defaults(func=cmd_rules)
    return p


def main(argv=None):
    _utf8()
    args = construir_parser().parse_args(argv)
    try:
        return args.func(args)
    except SecretscanError as e:
        print(f"erro: {e}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0
