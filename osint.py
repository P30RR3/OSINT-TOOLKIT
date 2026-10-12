#!/usr/bin/env python3
import sys
import os
import time
import socket
import ssl
import requests
import whois
import dns.resolver
from datetime import datetime
from urllib.parse import urlparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.align import Align
from rich.rule import Rule

os.system("")

console = Console()

VERSION = "v2.0"
AUTOR = "Alejandro"
C_MAIN = "bright_cyan"
C_OK = "bright_green"
C_ERR = "bright_red"
C_WARN = "bright_yellow"
C_DIM = "bright_black"
C_ACC = "bright_magenta"

BANNER_LINEA = "═" * 62


def limpiar():
    os.system("cls" if os.name == "nt" else "clear")


def gusano(duracion=2.0):
    frames = [
        "▸•        ",
        " ▸•       ",
        "  ▸•      ",
        "   ▸•     ",
        "    ▸•    ",
        "     ▸•   ",
        "      ▸•  ",
        "       ▸• ",
        "        ▸•",
        "       •▸ ",
        "      •▸  ",
        "     •▸   ",
        "    •▸    ",
        "   •▸     ",
        "  •▸      ",
        " •▸       ",
        "•▸        ",
    ]
    fin = time.time() + duracion
    i = 0
    while time.time() < fin:
        f = frames[i % len(frames)]
        linea = f"[{C_MAIN}]{f}[/]"
        sys.stdout.write(f"\r{linea}")
        sys.stdout.flush()
        time.sleep(0.08)
        i += 1
    sys.stdout.write("\r" + " " * 20 + "\r")
    sys.stdout.flush()


def banner_epico():
    limpiar()
    console.print()
    console.print(Align.center(f"[bold {C_MAIN}]▸▸▸  E L I X Y R   O S I N T   T O O L K I T  ◂◂◂[/]"))
    console.print(Align.center(f"[{C_DIM}]              {VERSION}  ▸  uso ético únicamente  ▸  by {AUTOR}[/]"))
    console.print(Align.center(f"[{C_DIM}]{BANNER_LINEA}[/]"))
    console.print()
    console.print(f"  [{C_ACC}]▸ inicializando sistemas...[/]")
    gusano(1.5)
    console.print(f"  [{C_OK}]▸ listo[/]")
    console.print()


def cargando(mensaje):
    return Progress(
        SpinnerColumn(style=C_MAIN),
        TextColumn(f"[{C_MAIN}]{mensaje}[/]"),
        transient=True,
        console=console,
    )


def pausa():
    console.print()
    Prompt.ask(f"[{C_DIM}]  ▸ Enter para volver[/]", default="")


# ─────────────────────────────────────────────
#  MÓDULOS
# ─────────────────────────────────────────────

def mod_whois(dominio):
    banner_epico()
    console.print(f"  [{C_MAIN}]▸ MÓDULO:[/] [{C_OK}]WHOIS[/]  [{C_DIM}]→ {dominio}[/]\n")
    try:
        with cargando("Consultando WHOIS..."):
            w = whois.whois(dominio)
        t = Table(show_header=False, border_style=C_MAIN, padding=(0, 2))
        t.add_column("C", style=f"bold {C_MAIN}")
        t.add_column("V", style="white")
        t.add_row("Registrador", str(w.registrar or "N/A"))
        t.add_row("Creado", str(w.creation_date or "N/A"))
        t.add_row("Expira", str(w.expiration_date or "N/A"))
        t.add_row("Actualizado", str(w.updated_date or "N/A"))
        t.add_row("Name servers", ", ".join(w.name_servers) if w.name_servers else "N/A")
        t.add_row("Estado", str(w.status or "N/A"))
        t.add_row("Email", str(w.emails or "N/A"))
        console.print(t)
    except Exception as e:
        console.print(f"  [{C_ERR}][!] Error: {e}[/]")


def mod_dns(dominio):
    banner_epico()
    console.print(f"  [{C_MAIN}]▸ MÓDULO:[/] [{C_OK}]DNS[/]  [{C_DIM}]→ {dominio}[/]\n")
    t = Table(show_header=True, header_style=f"bold {C_MAIN}", border_style=C_MAIN)
    t.add_column("Tipo", style=f"bold {C_MAIN}", width=8)
    t.add_column("Valor", style="white")
    for tipo in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        try:
            for r in dns.resolver.resolve(dominio, tipo):
                t.add_row(tipo, r.to_text())
        except dns.resolver.NXDOMAIN:
            console.print(f"  [{C_ERR}][!] Dominio no existe[/]")
            return
        except Exception:
            continue
    console.print(t)


def mod_subdomain(dominio):
    banner_epico()
    console.print(f"  [{C_MAIN}]▸ MÓDULO:[/] [{C_OK}]SUBDOMINIOS[/]  [{C_DIM}]→ {dominio} (vía crt.sh)[/]\n")
    try:
        with cargando("Consultando Certificate Transparency..."):
            r = requests.get(f"https://crt.sh/?q=%25.{dominio}&output=json", timeout=20)
        if r.status_code != 200:
            console.print(f"  [{C_ERR}][!] crt.sh devolvió {r.status_code}[/]")
            return
        subs = set()
        for e in r.json():
            for n in e.get("name_value", "").split("\n"):
                n = n.strip().lower()
                if n.endswith(dominio) and "*" not in n:
                    subs.add(n)
        if not subs:
            console.print(f"  [{C_WARN}][!] No se encontraron subdominios[/]")
            return
        t = Table(show_header=True, header_style=f"bold {C_MAIN}", border_style=C_MAIN)
        t.add_column("#", style=C_DIM, width=4)
        t.add_column("Subdominio", style="white")
        for i, s in enumerate(sorted(subs), 1):
            t.add_row(str(i), s)
        console.print(t)
        console.print(f"\n  [{C_OK}][+] Total:[/] [bold]{len(subs)}[/] subdominios")
    except Exception as e:
        console.print(f"  [{C_ERR}][!] Error: {e}[/]")


def mod_ip(ip):
    banner_epico()
    console.print(f"  [{C_MAIN}]▸ MÓDULO:[/] [{C_OK}]IP INFO[/]  [{C_DIM}]→ {ip}[/]\n")
    try:
        with cargando("Consultando ip-api.com..."):
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query", timeout=10)
        d = r.json()
        if d.get("status") != "success":
            console.print(f"  [{C_ERR}][!] No se pudo obtener info[/]")
            return
        t = Table(show_header=False, border_style=C_MAIN, padding=(0, 2))
        t.add_column("C", style=f"bold {C_MAIN}")
        t.add_column("V", style="white")
        for k, v in [
            ("IP", d.get("query")), ("País", d.get("country")),
            ("Región", d.get("regionName")), ("Ciudad", d.get("city")),
            ("ISP", d.get("isp")), ("Org", d.get("org")), ("ASN", d.get("as")),
        ]:
            t.add_row(k, v or "N/A")
        console.print(t)
    except Exception as e:
        console.print(f"  [{C_ERR}][!] Error: {e}[/]")


def mod_headers(url):
    banner_epico()
    if not url.startswith("http"):
        url = "https://" + url
    console.print(f"  [{C_MAIN}]▸ MÓDULO:[/] [{C_OK}]HTTP HEADERS[/]  [{C_DIM}]→ {url}[/]\n")
    try:
        with cargando("Consultando cabeceras..."):
            r = requests.get(url, timeout=10, allow_redirects=True)
        t = Table(show_header=False, border_style=C_MAIN, padding=(0, 2))
        t.add_column("C", style=f"bold {C_MAIN}")
        t.add_column("V", style="white")
        t.add_row("Status", str(r.status_code))
        t.add_row("Server", r.headers.get("Server", "N/A"))
        t.add_row("Powered-By", r.headers.get("X-Powered-By", "N/A"))
        console.print(t)

        console.print(f"\n  [{C_MAIN}]▸ Cabeceras de seguridad:[/]\n")
        ts = Table(show_header=True, header_style=f"bold {C_MAIN}", border_style=C_MAIN)
        ts.add_column("Cabecera", style=f"bold {C_MAIN}")
        ts.add_column("Estado", style="white")
        for h in ["Strict-Transport-Security", "Content-Security-Policy",
                  "X-Frame-Options", "X-Content-Type-Options",
                  "Referrer-Policy", "Permissions-Policy"]:
            v = r.headers.get(h)
            ts.add_row(h, f"[{C_OK}]✓ {v}[/]" if v else f"[{C_ERR}]✗ Ausente[/]")
        console.print(ts)
    except Exception as e:
        console.print(f"  [{C_ERR}][!] Error: {e}[/]")


def mod_email(correo):
    banner_epico()
    console.print(f"  [{C_MAIN}]▸ MÓDULO:[/] [{C_OK}]EMAIL BREACH[/]  [{C_DIM}]→ {correo}[/]\n")
    try:
        with cargando("Consultando HaveIBeenPwned..."):
            r = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{correo}",
                             headers={"User-Agent": "Elixyr-OSINT"}, timeout=10)
        if r.status_code == 200:
            b = r.json()
            console.print(f"  [{C_ERR}][!] Encontrado en {len(b)} filtraciones:[/]\n")
            t = Table(show_header=True, header_style=f"bold {C_ERR}", border_style=C_ERR)
            t.add_column("Filtración", style="white")
            t.add_column("Fecha", style=C_DIM)
            for x in b:
                t.add_row(x.get("Name", "N/A"), x.get("BreachDate", "N/A"))
            console.print(t)
        elif r.status_code == 404:
            console.print(f"  [{C_OK}][+] No encontrado en filtraciones conocidas[/]")
        elif r.status_code == 401:
            console.print(f"  [{C_WARN}][!] HIBP requiere API key[/]")
            console.print(f"  [{C_DIM}]    https://haveibeenpwned.com/API/Key[/]")
        else:
            console.print(f"  [{C_ERR}][!] Error: {r.status_code}[/]")
    except Exception as e:
        console.print(f"  [{C_ERR}][!] Error: {e}[/]")


def mod_ssl(dominio):
    banner_epico()
    console.print(f"  [{C_MAIN}]▸ MÓDULO:[/] [{C_OK}]SSL CERT[/]  [{C_DIM}]→ {dominio}[/]\n")
    try:
        with cargando("Consultando certificado..."):
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=dominio) as s:
                s.settimeout(10)
                s.connect((dominio, 443))
                cert = s.getpeercert()
        t = Table(show_header=False, border_style=C_MAIN, padding=(0, 2))
        t.add_column("C", style=f"bold {C_MAIN}")
        t.add_column("V", style="white")
        t.add_row("Sujeto", str(cert.get("subject", "N/A")))
        t.add_row("Emisor", str(cert.get("issuer", "N/A")))
        t.add_row("Válido desde", cert.get("notBefore", "N/A"))
        t.add_row("Válido hasta", cert.get("notAfter", "N/A"))
        t.add_row("SANs", ", ".join([x[1] for x in cert.get("subjectAltName", [])]) or "N/A")
        console.print(t)
    except Exception as e:
        console.print(f"  [{C_ERR}][!] Error: {e}[/]")


def mod_robots(dominio):
    banner_epico()
    if not dominio.startswith("http"):
        dominio = "https://" + dominio
    console.print(f"  [{C_MAIN}]▸ MÓDULO:[/] [{C_OK}]ROBOTS.TXT[/]  [{C_DIM}]→ {dominio}[/]\n")
    try:
        with cargando("Consultando robots.txt..."):
            r = requests.get(dominio.rstrip("/") + "/robots.txt", timeout=10)
        if r.status_code != 200:
            console.print(f"  [{C_ERR}][!] robots.txt devolvió {r.status_code}[/]")
            return
        console.print(f"  [{C_OK}]▸ Contenido:[/]\n")
        for linea in r.text.splitlines():
            if linea.startswith("Disallow"):
                console.print(f"    [{C_ERR}]{linea}[/]")
            elif linea.startswith("Allow"):
                console.print(f"    [{C_OK}]{linea}[/]")
            elif linea.startswith("User-agent"):
                console.print(f"    [{C_MAIN}]{linea}[/]")
            elif linea.startswith("Sitemap"):
                console.print(f"    [{C_ACC}]{linea}[/]")
            else:
                console.print(f"    [{C_DIM}]{linea}[/]")
    except Exception as e:
        console.print(f"  [{C_ERR}][!] Error: {e}[/]")


def mod_wayback(dominio):
    banner_epico()
    console.print(f"  [{C_MAIN}]▸ MÓDULO:[/] [{C_OK}]WAYBACK MACHINE[/]  [{C_DIM}]→ {dominio}[/]\n")
    try:
        with cargando("Consultando archive.org..."):
            r = requests.get(f"http://archive.org/wayback/available?url={dominio}", timeout=10)
        d = r.json()
        snap = d.get("archived_snapshots", {}).get("closest", {})
        if not snap:
            console.print(f"  [{C_WARN}][!] No hay capturas archivadas[/]")
            return
        t = Table(show_header=False, border_style=C_MAIN, padding=(0, 2))
        t.add_column("C", style=f"bold {C_MAIN}")
        t.add_column("V", style="white")
        t.add_row("Disponible", str(snap.get("available")))
        t.add_row("URL", snap.get("url", "N/A"))
        t.add_row("Timestamp", snap.get("timestamp", "N/A"))
        t.add_row("Status", str(snap.get("status")))
        console.print(t)
    except Exception as e:
        console.print(f"  [{C_ERR}][!] Error: {e}[/]")


def mod_tech(dominio):
    banner_epico()
    if not dominio.startswith("http"):
        dominio = "https://" + dominio
    console.print(f"  [{C_MAIN}]▸ MÓDULO:[/] [{C_OK}]TECH DETECT[/]  [{C_DIM}]→ {dominio}[/]\n")
    try:
        with cargando("Analizando tecnologías..."):
            r = requests.get(dominio, timeout=10, allow_redirects=True)
        html = r.text.lower()
        headers = r.headers
        tecs = []
        firmas = {
            "WordPress": ["wp-content", "wp-includes"],
            "Drupal": ["drupal", "sites/default"],
            "Joomla": ["joomla", "/components/com_"],
            "React": ["react", "_react"],
            "Vue.js": ["vue.js", "vue.min"],
            "Angular": ["ng-app", "angular"],
            "Bootstrap": ["bootstrap.min", "bootstrap.css"],
            "jQuery": ["jquery"],
            "Cloudflare": ["cloudflare"],
            "Nginx": ["nginx"],
            "Apache": ["apache"],
            "PHP": ["php"],
            "ASP.NET": ["asp.net"],
        }
        for tec, patrones in firmas.items():
            if any(p in html for p in patrones):
                tecs.append(tec)
        server = headers.get("Server", "")
        powered = headers.get("X-Powered-By", "")
        if server:
            tecs.append(f"Server: {server}")
        if powered:
            tecs.append(f"Powered-By: {powered}")

        if not tecs:
            console.print(f"  [{C_WARN}][!] No se detectaron tecnologías[/]")
            return
        t = Table(show_header=True, header_style=f"bold {C_MAIN}", border_style=C_MAIN)
        t.add_column("#", style=C_DIM, width=4)
        t.add_column("Tecnología", style="white")
        for i, tec in enumerate(sorted(set(tecs)), 1):
            t.add_row(str(i), tec)
        console.print(t)
    except Exception as e:
        console.print(f"  [{C_ERR}][!] Error: {e}[/]")


# ─────────────────────────────────────────────
#  MENÚ
# ─────────────────────────────────────────────

MODULOS = {
    "1": ("WHOIS", mod_whois, "Dominio", "  Info de un dominio"),
    "2": ("DNS", mod_dns, "Dominio", "  Registros A, MX, TXT, NS..."),
    "3": ("SUBDOMINIOS", mod_subdomain, "Dominio", "  Enumera vía crt.sh"),
    "4": ("IP INFO", mod_ip, "IP", "  Geolocalización + ISP"),
    "5": ("HTTP HEADERS", mod_headers, "URL", "  Cabeceras + seguridad"),
    "6": ("EMAIL BREACH", mod_email, "Correo", "  HaveIBeenPwned"),
    "7": ("SSL CERT", mod_ssl, "Dominio", "  Info del certificado"),
    "8": ("ROBOTS.TXT", mod_robots, "Dominio", "  Parser de robots.txt"),
    "9": ("WAYBACK", mod_wayback, "Dominio", "  Capturas en archive.org"),
    "10": ("TECH DETECT", mod_tech, "URL", "  Detector de tecnologías"),
    "0": ("SALIR", None, None, "  Terminar sesión"),
}


def menu():
    banner_epico()

    contenido = []
    contenido.append(f"[bold {C_ACC}]    ╔════════════════════════════════════════════════════╗[/]")
    contenido.append(f"[bold {C_ACC}]    ║          ▸ MÓDULOS DISPONIBLES ◂                  ║[/]")
    contenido.append(f"[bold {C_ACC}]    ╚════════════════════════════════════════════════════╝[/]")
    contenido.append("")

    for key in ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "0"]:
        nombre, _, _, desc = MODULOS[key]
        color = C_ERR if key == "0" else C_MAIN
        contenido.append(f"      [{color}][{key:>2}][/]  [bold white]{nombre:<14}[/] [{C_DIM}]{desc}[/]")

    contenido.append("")
    console.print("\n".join(contenido))

    opcion = Prompt.ask(f"  [{C_MAIN}]▸ Selecciona un módulo[/]", default="0")

    if opcion == "0" or opcion not in MODULOS:
        console.print(f"\n  [{C_DIM}]▸ Cerrando sesión...[/]")
        gusano(1.0)
        console.print(f"  [{C_OK}]▸ Hasta luego, {AUTOR}.[/]\n")
        sys.exit(0)

    nombre, func, campo, _ = MODULOS[opcion]
    valor = Prompt.ask(f"  [{C_MAIN}]▸ {campo}[/]")
    func(valor)
    pausa()


def main():
    while True:
        try:
            menu()
        except KeyboardInterrupt:
            console.print(f"\n  [{C_DIM}]▸ Interrumpido.[/]\n")
            sys.exit(0)


if __name__ == "__main__":
    main()