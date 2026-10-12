# ▸ Elixyr OSINT Toolkit

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

Herramienta CLI de OSINT escrita en Python. Interfaz interactiva con tema dark, animaciones y 10 módulos de reconocimiento pasivo usando APIs públicas.

> ⚠️ **Uso ético únicamente.** Solo consulta información pública. No atacar sistemas sin autorización.

---

## ▸ Módulos

| # | Módulo | Descripción |
|---|--------|-------------|
| 1 | WHOIS | Info de registro de un dominio |
| 2 | DNS | Registros A, AAAA, MX, NS, TXT, CNAME |
| 3 | Subdominios | Enumeración vía Certificate Transparency (crt.sh) |
| 4 | IP Info | Geolocalización, ISP, ASN |
| 5 | HTTP Headers | Análisis de cabeceras + seguridad |
| 6 | Email Breach | Verifica filtraciones (HaveIBeenPwned) |
| 7 | SSL Cert | Info del certificado SSL |
| 8 | robots.txt | Parser de robots.txt |
| 9 | Wayback | Capturas históricas (archive.org) |
| 10 | Tech Detect | Detector de tecnologías web |

---

## ▸ Instalación

```bash
git clone https://github.com/TU-USUARIO/osint-toolkit.git
cd osint-toolkit
pip install -r requirements.txt
