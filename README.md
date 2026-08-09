# 🌐 SubEnum

Herramienta de línea de comandos desarrollada en Python para la enumeración de subdominios y vHosts, diseñada específicamente para pruebas de penetración en entornos HTB y CTFs. Combina tres técnicas en paralelo: fuerza bruta DNS, enumeración de vHosts y consulta de certificados en crt.sh.

---

## Módulos

| Módulo | Técnica | Descripción |
|--------|---------|-------------|
| **DNS Bruteforce** | Resolución DNS | Prueba subdominios contra el servidor DNS del objetivo usando una wordlist |
| **vHost Enumeration** | HTTP Host header | Detecta vHosts ocultos enviando peticiones con cabeceras `Host` personalizadas |
| **crt.sh** | Certificate Transparency | Consulta registros de certificados SSL/TLS públicos para descubrir subdominios |

---

## Instalación

```bash
git clone https://github.com/darkstinx/SubEnum
cd SubEnum
pip install -r requirements.txt
```

---

## Uso

```bash
# Enumeración completa (DNS + crt.sh, sin vHost)
python3 subenum.py target.htb

# Enumeración completa con vHost (requiere IP)
python3 subenum.py target.htb --ip 10.129.44.248

# vHost en puerto 443
python3 subenum.py target.htb --ip 10.129.44.248 --port 443

# Wordlist personalizada
python3 subenum.py target.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

# Solo vHost, exportando resultados
python3 subenum.py target.htb --ip 10.129.44.248 --no-dns --no-crtsh -o resultados.txt

# Más hilos para mayor velocidad
python3 subenum.py target.htb --ip 10.129.44.248 -t 100
```

### Flags

| Flag | Descripción |
|------|-------------|
| `domain` | Dominio objetivo (ej: `target.htb`) |
| `-w, --wordlist` | Ruta a la wordlist. Por defecto: SecLists `subdomains-top1million-5000.txt` |
| `--ip` | IP del objetivo para vHost enumeration |
| `--port` | Puerto para vHost (default: `80`) |
| `--no-dns` | Saltar DNS bruteforce |
| `--no-vhost` | Saltar vHost enumeration |
| `--no-crtsh` | Saltar consulta a crt.sh |
| `-t, --threads` | Hilos paralelos (default: `50`) |
| `--timeout` | Timeout en segundos (default: `3`) |
| `-o, --output` | Exportar resultados a archivo TXT |

---

## Wordlist por defecto

SubEnum busca automáticamente SecLists en la ruta estándar de Kali Linux:

```
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

Si no se encuentra, utiliza una wordlist interna con los subdominios más comunes (~80 entradas) para poder ejecutarse sin dependencias adicionales en máquinas objetivo.

---

## Ejemplo de output

```
  🌐 SubEnum
  Enumerador de subdominios y vHosts · v1.0

  Dominio:  target.htb
  Hilos:    50
  Timeout:  3s
  IP:       10.129.44.248:80

──────────── DNS Bruteforce ────────────
  ✓ www.target.htb → 10.129.44.248

──────────── vHost Enumeration ────────────
  ✓ sub.target.htb → 200 (4821 bytes)

──────────── crt.sh ────────────
  (sin resultados para dominios .htb locales)

──────────── Resumen ────────────
┌──────────────────────┬─────────────┐
│ Módulo               │ Encontrados │
├──────────────────────┼─────────────┤
│ DNS Bruteforce       │      1      │
│ vHost Enumeration    │      1      │
│ crt.sh               │      0      │
│ Total únicos         │      2      │
└──────────────────────┴─────────────┘
```

---

## Requisitos

- Python 3.10+
- [rich](https://github.com/Textualize/rich)
- SecLists (opcional, recomendado en Kali Linux)

---

## Tecnologías

| Componente | Detalle |
|------------|---------|
| Lenguaje | Python 3.10+ |
| Interfaz | rich |
| Paralelismo | `concurrent.futures.ThreadPoolExecutor` |
| Módulos | `socket`, `urllib`, `ssl` (stdlib) |
| Entorno | Linux (probado en Kali Linux) |

---

## Autor

**Ignacio González Domínguez**  
[GitHub](https://github.com/darkstinx) · [LinkedIn](https://www.linkedin.com/in/ignacio-gonzalez-dominguez/) · [Portfolio](https://darkstinx.github.io)
