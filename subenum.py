#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════╗
║           SubEnum v1.0                       ║
║   Enumerador de subdominios y vHosts         ║
║   DNS · vHost · crt.sh · Paralelo            ║
╚══════════════════════════════════════════════╝
"""

import argparse
import concurrent.futures
import json
import re
import socket
import sys
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich import box

console = Console()

# ── Colores ───────────────────────────────────────────────────────────────────
COLOR_TITLE  = "bold magenta"
COLOR_INFO   = "bold cyan"
COLOR_OK     = "bold green"
COLOR_WARN   = "bold yellow"
COLOR_DANGER = "bold red"
COLOR_DIM    = "dim white"

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_THREADS    = 50
DEFAULT_TIMEOUT    = 3
DEFAULT_WORDLIST   = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
FALLBACK_WORDLIST  = [
    "www", "mail", "ftp", "admin", "api", "dev", "test", "staging", "app",
    "portal", "vpn", "blog", "shop", "forum", "git", "gitlab", "jenkins",
    "ci", "cdn", "static", "media", "assets", "upload", "uploads", "images",
    "ns1", "ns2", "smtp", "pop", "imap", "webmail", "remote", "mx", "mx1",
    "mx2", "internal", "intranet", "corp", "backend", "frontend", "dashboard",
    "monitor", "nagios", "zabbix", "grafana", "kibana", "elastic", "db",
    "database", "mysql", "postgres", "redis", "mongo", "backup", "old",
    "beta", "alpha", "demo", "secure", "login", "auth", "oauth", "sso",
    "id", "accounts", "billing", "pay", "payment", "support", "help", "docs",
    "wiki", "kb", "status", "health", "metrics", "stats", "analytics", "track",
    "mobile", "m", "wap", "api2", "v1", "v2", "v3", "ws", "websocket",
    "flow", "web", "node", "proxy", "gateway", "load", "lb", "ha", "uat",
]


# ── Banner ────────────────────────────────────────────────────────────────────
def mostrar_banner():
    banner = Text()
    banner.append("\n  🌐 SubEnum\n", style=COLOR_TITLE)
    banner.append("  Enumerador de subdominios y vHosts · v1.0\n", style=COLOR_DIM)
    console.print(Panel(banner, border_style="magenta", padding=(0, 2)))
    console.print()


# ── Carga de wordlist ─────────────────────────────────────────────────────────
def cargar_wordlist(path: str | None) -> list[str]:
    if path:
        p = Path(path)
        if not p.exists():
            console.print(f"  [red]✗ Wordlist no encontrada:[/red] {path}")
            sys.exit(1)
        words = [l.strip() for l in p.read_text(errors="replace").splitlines() if l.strip() and not l.startswith("#")]
        console.print(f"  [cyan]Wordlist:[/cyan] {path} ([green]{len(words):,} palabras[/green])")
        return words

    # Intentar SecLists por defecto
    default = Path(DEFAULT_WORDLIST)
    if default.exists():
        words = [l.strip() for l in default.read_text(errors="replace").splitlines() if l.strip()]
        console.print(f"  [cyan]Wordlist:[/cyan] SecLists ([green]{len(words):,} palabras[/green])")
        return words

    console.print(f"  [yellow]⚠  SecLists no encontrado. Usando wordlist interna ({len(FALLBACK_WORDLIST)} palabras).[/yellow]")
    return FALLBACK_WORDLIST


# ── DNS bruteforce ────────────────────────────────────────────────────────────
def dns_resolve(sub: str, domain: str, timeout: int) -> dict | None:
    fqdn = f"{sub}.{domain}"
    socket.setdefaulttimeout(timeout)
    try:
        ip = socket.gethostbyname(fqdn)
        return {"fqdn": fqdn, "ip": ip}
    except (socket.gaierror, socket.timeout):
        return None


def dns_bruteforce(domain: str, wordlist: list[str], threads: int, timeout: int) -> list[dict]:
    encontrados = []
    console.print()
    console.print(Rule("[cyan]DNS Bruteforce[/cyan]", style="cyan"))
    console.print(f"  [dim]Probando {len(wordlist):,} subdominios con {threads} hilos...[/dim]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}[/cyan]"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Resolviendo DNS...", total=len(wordlist))

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(dns_resolve, sub, domain, timeout): sub for sub in wordlist}
            for future in concurrent.futures.as_completed(futures):
                progress.advance(task)
                result = future.result()
                if result:
                    encontrados.append(result)
                    console.print(f"  [green]✓[/green] [bold]{result['fqdn']}[/bold] → [yellow]{result['ip']}[/yellow]")

    return encontrados


# ── vHost enumeration ─────────────────────────────────────────────────────────
def vhost_probe(sub: str, domain: str, ip: str, port: int, timeout: int, baseline_len: int) -> dict | None:
    vhost = f"{sub}.{domain}"
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{ip}:{port}/"

    req = urllib.request.Request(url)
    req.add_header("Host", vhost)
    req.add_header("User-Agent", "SubEnum/1.0")

    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            content = resp.read(4096)
            length  = int(resp.headers.get("Content-Length", len(content)))
            status  = resp.status
    except urllib.error.HTTPError as e:
        content = b""
        length  = 0
        status  = e.code
    except Exception:
        return None

    # Filtrar respuestas idénticas al baseline
    diff = abs(length - baseline_len)
    if diff < 50 and status in (200, 301, 302):
        return None

    return {"vhost": vhost, "status": status, "length": length}


def get_baseline(ip: str, domain: str, port: int, timeout: int) -> int:
    """Obtiene la longitud de respuesta por defecto para filtrar falsos positivos."""
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{ip}:{port}/"
    req = urllib.request.Request(url)
    req.add_header("Host", f"nonexistent-{domain}")
    req.add_header("User-Agent", "SubEnum/1.0")
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            content = resp.read(4096)
            return int(resp.headers.get("Content-Length", len(content)))
    except Exception:
        return 0


def vhost_enum(domain: str, ip: str, port: int, wordlist: list[str], threads: int, timeout: int) -> list[dict]:
    encontrados = []
    console.print()
    console.print(Rule("[cyan]vHost Enumeration[/cyan]", style="cyan"))
    console.print(f"  [dim]Target IP: {ip}:{port} | Probando {len(wordlist):,} vHosts...[/dim]")

    baseline = get_baseline(ip, domain, port, timeout)
    console.print(f"  [dim]Baseline response length: {baseline} bytes[/dim]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}[/cyan]"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Probando vHosts...", total=len(wordlist))

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(vhost_probe, sub, domain, ip, port, timeout, baseline): sub
                for sub in wordlist
            }
            for future in concurrent.futures.as_completed(futures):
                progress.advance(task)
                result = future.result()
                if result:
                    encontrados.append(result)
                    color = "green" if result["status"] == 200 else "yellow"
                    console.print(
                        f"  [{color}]✓[/{color}] [bold]{result['vhost']}[/bold] "
                        f"→ [{color}]{result['status']}[/{color}] "
                        f"[dim]({result['length']} bytes)[/dim]"
                    )

    return encontrados


# ── crt.sh ────────────────────────────────────────────────────────────────────
def crtsh_query(domain: str) -> list[str]:
    console.print()
    console.print(Rule("[cyan]crt.sh — Certificate Transparency[/cyan]", style="cyan"))
    console.print(f"  [dim]Consultando crt.sh para {domain}...[/dim]\n")

    url = f"https://crt.sh/?q=%.{domain}&output=json"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "SubEnum/1.0")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        console.print(f"  [red]✗ Error consultando crt.sh:[/red] {e}")
        return []

    subdominios = set()
    for entry in data:
        names = entry.get("name_value", "")
        for name in names.splitlines():
            name = name.strip().lstrip("*.")
            if name.endswith(f".{domain}") or name == domain:
                subdominios.add(name)

    if not subdominios:
        console.print("  [dim]No se encontraron entradas en crt.sh.[/dim]")
        return []

    encontrados = sorted(subdominios)
    for s in encontrados:
        console.print(f"  [green]✓[/green] [bold]{s}[/bold]")

    return encontrados


# ── Resumen final ─────────────────────────────────────────────────────────────
def mostrar_resumen(domain: str, dns_results: list, vhost_results: list, crtsh_results: list):
    console.print()
    console.print(Rule("[magenta]Resumen[/magenta]", style="magenta"))
    console.print()

    tabla = Table(box=box.ROUNDED, border_style="magenta", show_header=True, header_style="bold magenta")
    tabla.add_column("Módulo",       style="cyan",  min_width=22)
    tabla.add_column("Encontrados",  style="white", min_width=12, justify="center")

    tabla.add_row("DNS Bruteforce",             f"[green]{len(dns_results)}[/green]")
    tabla.add_row("vHost Enumeration",          f"[green]{len(vhost_results)}[/green]")
    tabla.add_row("crt.sh",                     f"[green]{len(crtsh_results)}[/green]")

    total = len(set(
        [r["fqdn"] for r in dns_results] +
        [r["vhost"] for r in vhost_results] +
        crtsh_results
    ))
    tabla.add_row("[bold]Total únicos[/bold]", f"[bold green]{total}[/bold green]")

    console.print(tabla)
    console.print()


# ── Exportar TXT ──────────────────────────────────────────────────────────────
def exportar_txt(domain: str, dns_results: list, vhost_results: list, crtsh_results: list, output: str):
    lineas = [
        f"# SubEnum v1.0 — {domain}",
        f"# {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]

    if dns_results:
        lineas.append("## DNS Bruteforce")
        for r in dns_results:
            lineas.append(f"{r['fqdn']} → {r['ip']}")
        lineas.append("")

    if vhost_results:
        lineas.append("## vHost Enumeration")
        for r in vhost_results:
            lineas.append(f"{r['vhost']} → {r['status']} ({r['length']} bytes)")
        lineas.append("")

    if crtsh_results:
        lineas.append("## crt.sh")
        for s in crtsh_results:
            lineas.append(s)
        lineas.append("")

    Path(output).write_text("\n".join(lineas), encoding="utf-8")
    console.print(f"  [green]✓[/green] Resultados exportados a [bold]{output}[/bold]\n")


# ── Resolución automática de IP ───────────────────────────────────────────────
def resolver_ip(domain: str, timeout: int) -> str | None:
    """
    Intenta resolver la IP del dominio usando el sistema local (incluye /etc/hosts).
    Funciona con dominios .htb añadidos manualmente al /etc/hosts de Kali.
    """
    socket.setdefaulttimeout(timeout)
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except (socket.gaierror, socket.timeout):
        return None


# ── CLI ───────────────────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        prog="subenum",
        description="Enumerador de subdominios y vHosts para HTB y CTFs.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("domain",                   help="Dominio objetivo (ej: fireflow.htb)")
    parser.add_argument("-w", "--wordlist",          help="Ruta a la wordlist. Por defecto: SecLists subdomains-top1million-5000.txt")
    parser.add_argument("--ip",                      help="IP del objetivo para vHost enumeration. Si no se especifica, se resuelve automáticamente desde /etc/hosts.")
    parser.add_argument("--port",   type=int, default=80, help="Puerto HTTP/HTTPS para vHost (default: 80)")
    parser.add_argument("--no-dns", action="store_true",  help="Saltar DNS bruteforce")
    parser.add_argument("--no-vhost", action="store_true", help="Saltar vHost enumeration")
    parser.add_argument("--no-crtsh", action="store_true", help="Saltar consulta a crt.sh")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help=f"Hilos paralelos (default: {DEFAULT_THREADS})")
    parser.add_argument("--timeout",   type=int, default=DEFAULT_TIMEOUT,  help=f"Timeout en segundos (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-o", "--output", help="Archivo TXT de salida (ej: resultados.txt)")
    return parser.parse_args()


def main():
    args = parse_args()
    mostrar_banner()

    # Resolver IP automáticamente si no se especifica
    ip = args.ip
    if not ip and not args.no_vhost:
        ip = resolver_ip(args.domain, args.timeout)
        if ip:
            console.print(f"  [dim]IP resuelta automáticamente desde /etc/hosts: {ip}[/dim]")
        else:
            console.print(f"  [yellow]⚠  No se pudo resolver la IP de {args.domain}.[/yellow]")
            console.print(f"  [dim]Asegúrate de tener el dominio en /etc/hosts o usa --ip <IP>.[/dim]")

    console.print(f"  [cyan]Dominio:[/cyan]  {args.domain}")
    console.print(f"  [cyan]Hilos:[/cyan]    {args.threads}")
    console.print(f"  [cyan]Timeout:[/cyan]  {args.timeout}s")
    if ip:
        console.print(f"  [cyan]IP:[/cyan]       {ip}:{args.port}")
    console.print()

    wordlist    = cargar_wordlist(args.wordlist)
    dns_results    = []
    vhost_results  = []
    crtsh_results  = []

    # DNS bruteforce
    if not args.no_dns:
        dns_results = dns_bruteforce(args.domain, wordlist, args.threads, args.timeout)

    # vHost enumeration
    if not args.no_vhost:
        if not ip:
            console.print("  [yellow]⚠  Sin IP disponible. Saltando vHost enumeration.[/yellow]")
        else:
            vhost_results = vhost_enum(args.domain, ip, args.port, wordlist, args.threads, args.timeout)

    # crt.sh
    if not args.no_crtsh:
        crtsh_results = crtsh_query(args.domain)

    # Resumen
    mostrar_resumen(args.domain, dns_results, vhost_results, crtsh_results)

    # Exportar
    if args.output:
        exportar_txt(args.domain, dns_results, vhost_results, crtsh_results, args.output)


if __name__ == "__main__":
    main()