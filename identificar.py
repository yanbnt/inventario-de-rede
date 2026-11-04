"""
Identificação de dispositivos e serviços + inventário persistente.

- Fabricante pelo MAC (base IEEE em dados/oui.csv)
- Categoria do dispositivo por pontuação de evidências (fabricante, portas, páginas web, nome)
- Inventário em dados/inventario.json: nomes/categorias definidos por você, primeira/última vez visto
"""
import csv
import json
import os
import re
import socket
import subprocess
from datetime import datetime

import shutil
import sys

FROZEN = getattr(sys, "frozen", False)
# recursos somente leitura (no executável ficam dentro do pacote do PyInstaller)
BASE = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
# dados do usuário: instalado -> %LOCALAPPDATA%\InventarioRede\dados ; desenvolvimento -> ./dados
if os.environ.get("INVENTARIO_DADOS"):
    DADOS = os.environ["INVENTARIO_DADOS"]
elif FROZEN:
    DADOS = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "InventarioRede", "dados")
else:
    DADOS = os.path.join(BASE, "dados")
OUI_CSV = os.path.join(DADOS, "oui.csv")
OUI_SEED = os.path.join(BASE, "oui.csv")  # cópia embutida no instalador
INVENTARIO = os.path.join(DADOS, "inventario.json")
os.makedirs(DADOS, exist_ok=True)
if not os.path.exists(OUI_CSV) and os.path.exists(OUI_SEED):
    shutil.copyfile(OUI_SEED, OUI_CSV)
NOWIN = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW: não abre console ao chamar ping/arp/etc.

# ------------------------------------------------------------------ categorias
# id: (rótulo, ícone Material Symbols, categoria de serviço web)
DEV_CATS = {
    "roteador":     ("Rede & Wi-Fi", "router", "rede"),
    "camera":       ("Câmeras & CFTV", "videocam", "cftv"),
    "acesso":       ("Controle de Acesso", "face", "acesso"),
    "impressora":   ("Impressoras", "print", "impressao"),
    "servidor":     ("Servidores", "dns", "web"),
    "computador":   ("Computadores", "computer", "web"),
    "celular":      ("Celulares & Tablets", "smartphone", "web"),
    "tv":           ("TVs & Mídia", "tv", "web"),
    "iot":          ("IoT & Automação", "sensors", "web"),
    "voip":         ("Telefonia / VoIP", "call", "voip"),
    "desconhecido": ("Não identificados", "device_unknown", "web"),
}

SVC_CATS = [
    ("rede", "Rede & Infraestrutura", "router"),
    ("cftv", "Câmeras & CFTV", "videocam"),
    ("acesso", "Controle de Acesso", "face"),
    ("impressao", "Impressão", "print"),
    ("web", "Aplicações Web", "language"),
    ("remoto", "Acesso Remoto", "terminal"),
    ("arquivos", "Arquivos & Compartilhamentos", "folder_shared"),
    ("banco", "Bancos de Dados", "database"),
    ("voip", "Telefonia / VoIP", "call"),
    ("email", "E-mail", "mail"),
    ("sistema", "Serviços de Sistema", "settings"),
    ("outros", "Outros", "help"),
]

# porta -> (nome, categoria, esquema de link)
PORTS = {
    20: ("FTP dados", "arquivos", None), 21: ("FTP", "arquivos", "ftp"),
    22: ("SSH", "remoto", "ssh"), 23: ("Telnet", "remoto", "telnet"),
    25: ("SMTP", "email", None), 53: ("DNS", "rede", None), 67: ("DHCP", "rede", None),
    79: ("Finger", "outros", None), 88: ("Kerberos", "sistema", None),
    110: ("POP3", "email", None), 111: ("RPCbind", "sistema", None),
    123: ("NTP", "rede", None), 135: ("MS-RPC", "sistema", None),
    139: ("NetBIOS", "sistema", None), 143: ("IMAP", "email", None),
    161: ("SNMP", "rede", None), 389: ("LDAP", "sistema", None),
    445: ("Compartilhamento SMB", "arquivos", "smb"), 464: ("Kerberos passwd", "sistema", None),
    465: ("SMTPS", "email", None), 515: ("LPD (impressão)", "impressao", None),
    548: ("AFP", "arquivos", None), 554: ("RTSP (vídeo)", "cftv", "rtsp"),
    587: ("SMTP submissão", "email", None), 593: ("RPC sobre HTTP", "sistema", None),
    631: ("IPP (impressão)", "impressao", None), 636: ("LDAPS", "sistema", None),
    873: ("rsync", "arquivos", None), 993: ("IMAPS", "email", None), 995: ("POP3S", "email", None),
    1433: ("SQL Server", "banco", None), 1521: ("Oracle", "banco", None),
    1723: ("VPN PPTP", "rede", None), 1883: ("MQTT", "outros", None),
    2049: ("NFS", "arquivos", None), 2869: ("UPnP", "sistema", None),
    3050: ("Firebird", "banco", None), 3268: ("Catálogo Global AD", "sistema", None),
    3269: ("Catálogo Global AD (SSL)", "sistema", None),
    3306: ("MySQL / MariaDB", "banco", None), 3389: ("Área de Trabalho Remota (RDP)", "remoto", "rdp"),
    5040: ("Windows (CDP)", "sistema", None), 5060: ("SIP", "voip", None), 5061: ("SIP TLS", "voip", None),
    5357: ("WSD (descoberta)", "sistema", None), 5432: ("PostgreSQL", "banco", None),
    5900: ("VNC", "remoto", "vnc"), 5901: ("VNC", "remoto", "vnc"),
    5938: ("TeamViewer", "remoto", None), 5985: ("WinRM", "remoto", None), 5986: ("WinRM (HTTPS)", "remoto", None),
    6379: ("Redis", "banco", None), 6668: ("Tuya (IoT)", "outros", None),
    7070: ("AnyDesk", "remoto", None), 7680: ("Windows Update (DO)", "sistema", None),
    8008: ("Chromecast", "outros", None), 8009: ("Chromecast", "outros", None),
    8001: ("Smart TV (Samsung)", "outros", None), 8002: ("Smart TV (Samsung)", "outros", None),
    8291: ("MikroTik Winbox", "rede", None), 8554: ("RTSP (vídeo)", "cftv", "rtsp"),
    8728: ("MikroTik API", "rede", None), 9100: ("Impressão RAW (JetDirect)", "impressao", None),
    9101: ("Impressão RAW", "impressao", None), 9102: ("Impressão RAW", "impressao", None),
    27017: ("MongoDB", "banco", None), 34567: ("DVR (XMEye)", "cftv", None),
    37777: ("DVR/NVR (SDK Intelbras/Dahua)", "cftv", None), 37778: ("DVR/NVR (SDK)", "cftv", None),
    62078: ("iPhone/iPad (sincronização)", "outros", None),
    1716: ("KDE Connect", "outros", None), 2601: ("Quagga (roteamento)", "rede", None),
    5672: ("RabbitMQ (AMQP)", "outros", None), 7678: ("Samsung AllShare (DLNA)", "outros", None),
    9009: ("Gerência Intelbras", "rede", None), 8686: ("Câmera (gerência)", "cftv", None),
}
HTTP_FALLBACK = {80: "http", 8080: "http", 8000: "http", 8081: "http", 8888: "http", 81: "http",
                 443: "https", 8443: "https", 4443: "https"}

# ------------------------------------------------------------------ regras
VENDOR_RULES = [  # (regex do fabricante, categoria, peso, explicação)
    (r"hikvision|dahua|uniview|axis comm|hanwha|vivotek|ezviz|tiandy|xiongmai|jovision|tvt digital", "camera", 3, "fabricante de câmeras"),
    (r"ricoh|lexmark|canon|seiko epson|epson|brother|kyocera|xerox|konica|sharp corp|oki data|zebra|bematech|elgin|"
     r"hanin|hprt|printronix|toshiba tec|pantum|argox|tsc auto|datamax|honeywell print|godex|daruma|sweda", "impressora", 3, "fabricante de impressoras"),
    (r"mikrotik|routerboard|ubiquiti|tp-link|cisco|aruba|juniper|fortinet|ruckus|d-link|tenda|mercusys|"
     r"huawei technologies|zte corp|netgear|cambium|furukawa|datacom|sophos|palo alto|meraki|linksys|"
     r"ruijie|grandstream networks? \(ap\)|multilaser|elsys|greatek|draytek|edimax|zyxel|teltonika", "roteador", 3, "fabricante de equipamentos de rede"),
    (r"control ?id|henry equipamentos|topdata|zkteco|anviz|suprema|idemia", "acesso", 3, "fabricante de controle de acesso"),
    (r"grandstream|yealink|fanvil|polycom|snom|avaya|gigaset|khomp|digium|mitel|panasonic system", "voip", 3, "fabricante de telefonia IP"),
    (r"super micro|supermicro|vmware|synology|qnap|nutanix|hewlett packard enterprise|inspur", "servidor", 2, "fabricante de servidores/virtualização"),
    (r"apple|motorola|xiaomi|oppo|vivo mobile|oneplus|realme|huawei device|honor device|nokia|"
     r"sony mobile|lg electronics.*mobile|asus.*mobile|google|tcl communication|infinix|transsion|"
     r"guangdong oppo|zte mobile|positivo.*mobile|multilaser.*mobile", "celular", 2, "fabricante de celulares"),
    (r"realtek|intel corporate|giga-byte|asustek|asrock|micro-star|dell|lenovo|hp inc|hewlett|acer|azurewave|"
     r"liteon|lite-on|elitegroup|foxconn|hon hai|pegatron|quanta|wistron|compal|positivo|clevo|biostar|"
     r"qualcomm atheros|rivet networks|killer|intel corp|samsung electro-mechanics|universal global|"
     r"chicony|cloud network technology|liteon|tenda.*pc|daten|vaio|toshiba client|dynabook|microsoft corp", "computador", 2, "placa de rede de PC/notebook"),
    (r"roku|hisense|tcl king|vizio|philips|semp|aoc|sky|claro|netflix|amlogic|mstar|realtek.*tv|"
     r"sony visual|sony interactive|nintendo|microsoft xbox|lg innotek", "tv", 2, "fabricante de TVs/mídia"),
    (r"tuya|espressif|shenzhen bilian|amazon technologies|sonoff|itead|shelly|allterco|nest labs|ring llc|"
     r"linksprite|raspberry pi|wyze|broadlink|hangzhou|lumi united|xiaomi communications|signify|"
     r"positivo.*casa|ezviz.*smart|texas instruments|silicon labs|nordic semi|murata|ampak|"
     r"intelbras.*iot|shenzhen.*smart|smart life|govee|meross|aqara", "iot", 2, "fabricante de IoT/automação"),
    (r"samsung electronics", "celular", 1, "Samsung (celular, TV ou eletrodoméstico)"),
]
VENDOR_RULES = [(re.compile(r, re.I), c, w, e) for r, c, w, e in VENDOR_RULES]

TEXT_RULES = [  # títulos de página, banners, servidores
    (r"access control|control ?id|idface|idaccess|idflex|henry|topdata|catraca|facial|zkteco", "acesso", 5, "interface de controle de acesso"),
    (r"ricoh|lexmark|epson|brother|kyocera|xerox|canon|laserjet|officejet|deskjet|printer|impressora|"
     r"bematech|zebra|elgin|sp \d{4}|mx\d{3}", "impressora", 5, "interface de impressora"),
    (r"hikvision|dahua|\bdvr\b|\bnvr\b|\bipc\b|web service|camera|câmera|ezviz|xmeye|\bvms\b|imou|mibo", "camera", 4, "interface de câmera/DVR"),
    (r"mikrotik|routeros|unifi|ubiquiti|tp-link|mercusys|tenda|fortinet|fortigate|pfsense|opnsense|sophos|"
     r"router|roteador|aruba|cisco|d-link|ruijie|datacom|access point|wi-?fi|twibi|\bont\b|\bolt\b|gpon|"
     r"httpd_ac|wom|\bap\b \d+|mesh", "roteador", 4, "interface de equipamento de rede"),
    (r"pabx|\bpbx\b|grandstream|yealink|fanvil|asterisk|issabel|elastix|freepbx|voip|\bsip\b|impacta|unniti", "voip", 5, "interface de telefonia"),
    (r"smart ?tv|tizen|webos|android tv|chromecast|roku|dlna|kodi|plex|jellyfin", "tv", 4, "serviço de TV/mídia"),
    (r"synology|qnap|proxmox|vmware|esxi|idrac|ilo\b|truenas|unraid|zabbix|grafana|glpi|portainer|"
     r"microsoft-iis|sql server|veeam|nextcloud", "servidor", 4, "serviço típico de servidor"),
    (r"openssh_for_windows|microsoft", "computador", 1, "serviço Windows"),
]
TEXT_RULES = [(re.compile(r, re.I), c, w, e) for r, c, w, e in TEXT_RULES]

PORT_RULES = [  # (conjunto de portas, categoria, peso, explicação)
    ({554, 8554, 37777, 37778, 34567}, "camera", 4, "porta de vídeo/DVR aberta"),
    ({9100, 515, 631}, "impressora", 4, "porta de impressão aberta"),
    ({135, 445, 3389, 5985}, "computador", 3, "serviços Windows abertos"),
    ({53, 8291, 8728, 1723}, "roteador", 3, "DNS/gerência de rede aberta"),
    ({5060, 5061}, "voip", 4, "porta SIP aberta"),
    ({8001, 8002, 9197, 7676, 8008, 8009}, "tv", 4, "porta típica de Smart TV/Chromecast"),
    ({62078}, "celular", 5, "porta de sincronização do iPhone/iPad"),
    ({6668, 1883}, "iot", 3, "porta típica de IoT"),
    ({1433, 3306, 5432, 1521, 3050, 27017}, "servidor", 3, "banco de dados aberto"),
]

MODEL_RE = re.compile(r"(RICOH [A-Z]{1,3} ?\w+|Lexmark \w+|EPSON [\w-]+|Brother [\w-]+|KYOCERA [\w-]+|Canon [\w-]+|"
                      r"HP (?:LaserJet|OfficeJet|DeskJet|Color LaserJet)[\w -]*?\w+(?= |$)|Xerox [\w-]+|Samsung [\w-]+)", re.I)
GENERIC_TITLE = re.compile(r"\d{3}\b.*|HTTP Status \d{3}.*|Not Found|Forbidden|Index of.*|Document Moved|Object moved|"
                           r"Redirect.*|Loading.*|Web ?Server|index|home|login|WEB|Untitled|Document", re.I)

# ------------------------------------------------------------------ fabricantes
_OUI = None


def load_oui():
    global _OUI
    _OUI = {}
    if os.path.exists(OUI_CSV):
        with open(OUI_CSV, encoding="utf-8", errors="replace") as f:
            for r in csv.DictReader(f):
                _OUI[r["Assignment"].upper()] = r["Organization Name"].strip()
    return len(_OUI)


def tidy_vendor(v):
    v = re.sub(r",?\s*a lenovo company", "", v, flags=re.I)
    suf = re.compile(r"[\s,.]+(co\.?,?\s*ltd\.?|co|ltd\.?|corp(oration)?\.?|inc\.?|incorporated|ltda\.?|limited|llc|gmbh|"
                     r"s\.?a\.?|technologyco|technology|technologies|electronics|international|company|corporate)\.?$", re.I)
    prev = None
    while prev != v:
        prev, v = v, suf.sub("", v.strip())
    v = re.sub(r"\s+", " ", v).strip(" ,.-")
    return v.title() if v.isupper() and len(v) > 4 else v


def vendor(mac):
    if not mac:
        return None, False
    if _OUI is None:
        load_oui()
    h = mac.replace(":", "").replace("-", "").upper()
    private = len(h) >= 2 and bool(int(h[1], 16) & 2)
    return _OUI.get(h[:6]), private


# ------------------------------------------------------------------ rede local
def local_info():
    ip = gw = None
    try:
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sk.connect(("8.8.8.8", 80))  # não envia pacotes; só escolhe a interface
        ip = sk.getsockname()[0]
        sk.close()
    except Exception:
        pass
    try:
        out = subprocess.run(["route", "print", "0.0.0.0"], capture_output=True, creationflags=NOWIN).stdout.decode("cp850", "replace")
        m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out, re.M)
        gw = m.group(1) if m else None
    except Exception:
        pass
    return ip, gw


# ------------------------------------------------------------------ classificação
def svc_text(s):
    return " ".join(str(s.get(k, "")) for k in ("title", "server", "banner", "hint", "auth"))


def host_model(h):
    for s in h["servicos"]:
        for k in ("title", "banner", "server"):
            m = MODEL_RE.search(s.get(k) or "")
            if m:
                return m.group(1).strip()
    return None


def classify_device(h, vend, private, gw):
    """Retorna (categoria, confiança, evidências)."""
    ports = {s["port"] for s in h["servicos"]}
    name = (h.get("netbios") or h.get("hostname") or "")
    score, ev = {}, []

    def add(cat, w, why):
        score[cat] = score.get(cat, 0) + w
        ev.append(why)

    if h["ip"] == gw:
        add("roteador", 10, "é o gateway padrão da rede")
    if vend:
        for rx, cat, w, why in VENDOR_RULES:
            if rx.search(vend):
                add(cat, w, f"MAC {vend}: {why}")
                break
        else:
            if re.search(r"intelbras", vend, re.I):
                add("roteador", 1, "MAC Intelbras (faz câmeras, roteadores, APs e controle de acesso)")
            else:
                ev.append(f"MAC {vend}")
    elif private:
        known = set(PORTS) | set().union(*(p for p, *_ in PORT_RULES)) | set(HTTP_FALLBACK)
        if not ports:
            add("celular", 3, "MAC privado/aleatório e nenhuma porta aberta (típico de celular)")
        elif all(p > 1024 and p not in known for p in ports) and not any(s.get("proto") for s in h["servicos"]):
            add("celular", 3, "MAC privado/aleatório e só portas altas de aplicativos (típico de celular)")
        else:
            ev.append("MAC privado/aleatório")
    if vend and re.search(r"samsung electronics", vend, re.I) and ports:
        add("tv", 2, "Samsung com serviços de rede abertos (provável Smart TV)")
    for ps, cat, w, why in PORT_RULES:
        hit = ports & ps
        if hit:
            add(cat, w, f"{why} ({', '.join(map(str, sorted(hit)))})")
    text = " ".join(svc_text(s) for s in h["servicos"])
    seen = set()
    for rx, cat, w, why in TEXT_RULES:
        m = rx.search(text)
        if m and cat not in seen:
            seen.add(cat)
            add(cat, w, f"{why}: “{m.group(0)}”")
    if re.search(r"^(DESKTOP|LAPTOP|NOTEBOOK|PC|WIN|ESTACAO|NB)[-_]", name, re.I):
        add("computador", 3, f"nome de computador Windows ({name})")
    if re.search(r"SERV|SRV|SERVER|\bDC\d|^AD\d|NAS|STORAGE", name, re.I):
        add("servidor", 4, f"nome de servidor ({name})")
    if re.search(r"iphone|ipad|galaxy|android|redmi|moto[ -]", name, re.I):
        add("celular", 4, f"nome de celular ({name})")

    # computador com cara de servidor (Windows + serviços web/BD ou muitas portas)
    if score.get("computador", 0) and (ports & {80, 443, 8443, 1433, 3306, 5432} or len(ports) > 25):
        add("servidor", score["computador"] + 1 - score.get("servidor", 0), "Windows publicando serviços (web/BD) — provável servidor")

    if not score:
        return "desconhecido", "baixa", ev or ["sem evidências suficientes"]
    cat = max(score, key=score.get)
    top = score[cat]
    conf = "alta" if top >= 5 else "média" if top >= 3 else "baixa"
    return cat, conf, ev


def banner_service(b):
    if b.startswith("SSH-"):
        return "SSH", "remoto", "ssh"
    if b.startswith("RFB "):
        return "VNC", "remoto", "vnc"
    if b.startswith("220") and re.search(r"ftp", b, re.I):
        return "FTP", "arquivos", "ftp"
    if b.startswith("220") and re.search(r"smtp|esmtp|mail", b, re.I):
        return "SMTP", "email", None
    if b.startswith("+OK"):
        return "POP3", "email", None
    if b.startswith("* OK"):
        return "IMAP", "email", None
    if re.search(r"mysql|mariadb", b, re.I):
        return "MySQL / MariaDB", "banco", None
    if re.search(r"login:", b, re.I):
        return "Telnet", "remoto", "telnet"
    return None


def build_url(scheme, ip, port):
    defaults = {"http": 80, "https": 443, "ftp": 21, "ssh": 22}
    if scheme in ("http", "https", "ftp"):
        return f"{scheme}://{ip}/" if port == defaults[scheme] else f"{scheme}://{ip}:{port}/"
    if scheme == "ssh":
        return f"ssh://{ip}" if port == 22 else f"ssh://{ip}:{port}"
    if scheme in ("telnet", "vnc"):
        return f"{scheme}://{ip}:{port}"
    if scheme == "rtsp":
        return f"rtsp://{ip}:{port}/"
    return None


def count_unknown(h):
    """Quantas portas do host não têm serviço reconhecível (sem protocolo, banner nem porta conhecida)."""
    return sum(1 for s in h["servicos"] if not s.get("proto") and not s.get("banner")
               and s["port"] not in PORTS and s["port"] not in HTTP_FALLBACK)


def classify_service(h, s, dev, model=None, many_unknown=False):
    ip, port, proto = h["ip"], s["port"], s.get("proto")
    dev_cat = DEV_CATS[dev][2]
    tags, detail = [], []
    if s.get("tls") or proto == "https":
        tags.append("TLS")
    out = {"ip": ip, "port": port}

    noresp = False
    if proto is None and not s.get("banner") and port in HTTP_FALLBACK and dev != "computador":
        proto = HTTP_FALLBACK[port]
        noresp = not s.get("pend")
    if proto in ("http", "https"):
        nome = s.get("title") or ""
        if not nome or GENERIC_TITLE.fullmatch(nome):
            nome = model or s.get("hint") or ""
            if not nome:
                nome = {"camera": "Câmera / DVR", "impressora": "Impressora", "roteador": "Equipamento de rede",
                        "acesso": "Controle de acesso", "tv": "Smart TV", "voip": "Telefonia"}.get(dev) \
                    or s.get("server") or ""
            nome = f"Painel web — {nome}" if nome else "Interface web"
        elif re.fullmatch(r"[\w-]{2,15}", nome):
            nome = f"Painel web — {nome}"  # título só com a marca (ex.: "Intelbras")
        if noresp:
            detail.append("não respondeu à sondagem HTTP")
        out.update(cat=dev_cat, nome=nome, url=build_url(proto, ip, port), tipo=proto.upper())
        if s.get("server") and s["server"] not in nome:
            detail.append(s["server"])
        code = re.search(r"\s(\d{3})", s.get("status", ""))
        if code:
            c = code.group(1)
            if c == "401":
                tags.append("LOGIN")
            elif c.startswith("3") and s.get("location"):
                detail.append("→ " + s["location"])
            elif c.startswith(("4", "5")):
                tags.append(c)
        m = re.search(r'realm="([^"]+)"', s.get("auth") or "")
        if m:
            detail.append("realm: " + m.group(1))
    else:
        known = PORTS.get(port)
        bs = banner_service(s.get("banner", "")) if s.get("banner") else None
        if proto == "rtsp":
            known = ("RTSP (vídeo)", "cftv", "rtsp")
        elif proto in ("raw-print", "lpd"):
            known = PORTS.get(port) or ("Impressão", "impressao", None)
        elif bs:
            known = bs
        elif port == 3389:
            known = PORTS[3389]
        if known is None:
            if dev in ("computador", "servidor") and port >= 49152:
                known = ("RPC dinâmico", "sistema", None)
            elif many_unknown and proto is None and not s.get("banner"):
                known = (f"Porta dinâmica {port}", "sistema", None)
            elif dev == "camera" and port in (8000, 8200, 9010, 9020):
                known = ("SDK câmera (Hikvision/Intelbras)", "cftv", None)
            else:
                known = (f"Porta {port}" + (" (TLS)" if proto == "tls" else ""), "outros", None)
        nome, cat, scheme = known
        if port == 554 and dev not in ("camera", "acesso") and proto != "rtsp":
            cat = "outros"
        out.update(cat=cat, nome=nome, tipo=nome.split(" ")[0].upper())
        if scheme == "rdp":
            out["rdp"] = ip if port == 3389 else f"{ip}:{port}"
            out["copy"] = f"mstsc /v:{out['rdp']}"
        elif scheme == "smb":
            out["copy"] = f"\\\\{ip}"
        elif scheme:
            out["url"] = build_url(scheme, ip, port)
        b = s.get("banner") or ""
        if b and (b.count("�") > 2 or len(re.sub(r"[\w\s.,:;/()\-]", "", b)) > len(b) * 0.3):
            b = "responde com dados binários"
        if b:
            detail.append(b[:120])
        if s.get("server"):
            detail.append(s["server"])
    if s.get("pend"):
        tags.append("IDENTIFICANDO")
    out["tags"] = tags
    out["det"] = " · ".join(d for d in detail if d)
    out.setdefault("copy", out.get("url") or f"{ip}:{port}")
    return out


# ------------------------------------------------------------------ inventário
def load_inv():
    try:
        with open(INVENTARIO, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"dispositivos": {}, "varreduras": []}


def save_inv(inv):
    tmp = INVENTARIO + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(inv, f, ensure_ascii=False, indent=1)
    os.replace(tmp, INVENTARIO)


def key_of(h):
    return h["mac"].upper() if h.get("mac") else "IP:" + h["ip"]


def register_scan(d, inv=None):
    """Atualiza primeira/última vez visto. Idempotente por varredura (usa d['fim'])."""
    inv = inv or load_inv()
    marca = d.get("fim")
    if not marca or marca in inv["varreduras"]:
        return inv
    for h in d["hosts"]:
        k = key_of(h)
        e = inv["dispositivos"].setdefault(k, {"primeiro": marca})
        e["ultimo"] = marca
        e["ip"] = h["ip"]
        ips = e.setdefault("ips", [])
        if h["ip"] not in ips:
            ips.append(h["ip"])
            del ips[:-5]
        if h.get("netbios") or h.get("hostname"):
            e["nome_rede"] = h.get("netbios") or h.get("hostname")
    inv["varreduras"].append(marca)
    del inv["varreduras"][:-50]
    save_inv(inv)
    return inv


def update_device(chave, nome=None, categoria=None, notas=None):
    inv = load_inv()
    e = inv["dispositivos"].setdefault(chave, {})
    if nome is not None:
        e["nome"] = nome.strip()[:80]
    if categoria is not None:
        e["categoria"] = categoria if categoria in DEV_CATS else ""
    if notas is not None:
        e["notas"] = notas.strip()[:1000]
    save_inv(inv)
    return e


# ------------------------------------------------------------------ payload
def build_payload(d, inv=None, parcial=False):
    inv = inv or load_inv()
    my_ip, gw = local_info()
    devices, servs = [], []
    seen = set()
    first_scan = len(inv.get("varreduras", [])) <= 1
    for h in d["hosts"]:
        k = key_of(h)
        seen.add(k)
        e = inv["dispositivos"].get(k, {})
        vend, private = vendor(h.get("mac"))
        cat_auto, conf, ev = classify_device(h, vend, private, gw)
        cat = e.get("categoria") or cat_auto
        model = host_model(h)
        nome_rede = h.get("netbios") or (h.get("hostname") or "").removesuffix(".local") or ""
        if re.fullmatch(r"[0-9A-F]{12}", nome_rede, re.I):
            nome_rede = ""
        auto_nome = nome_rede
        if model and model.upper() not in nome_rede.upper():
            auto_nome = f"{model} ({nome_rede})" if nome_rede else model
        hs = []
        many = count_unknown(h) > 15  # ex.: impressoras Ricoh expõem centenas de portas internas
        if many:
            ev.append(f"{count_unknown(h)} portas abertas sem serviço reconhecível (agrupadas em Serviços de Sistema)")
        for s in sorted(h["servicos"], key=lambda x: x["port"]):
            c = classify_service(h, s, cat, model, many)
            c["chave"] = k
            hs.append(c)
            servs.append(c)
        devices.append({
            "chave": k, "ip": h["ip"], "mac": h.get("mac") or "", "fabricante": tidy_vendor(vend) if vend else "",
            "fabricante_full": vend or "", "mac_privado": private,
            "nome": e.get("nome") or auto_nome, "nome_auto": auto_nome, "nome_rede": nome_rede, "modelo": model or "",
            "cat": cat, "cat_auto": cat_auto, "manual": bool(e.get("categoria")), "confianca": conf, "evidencias": ev,
            "tag": "gateway" if h["ip"] == gw else ("este computador" if h["ip"] == my_ip else ""),
            "online": True, "ping": h.get("ping"), "notas": e.get("notas", ""),
            "primeiro": e.get("primeiro", d.get("fim")), "ultimo": e.get("ultimo", d.get("fim")),
            "novo": (not first_scan) and e.get("primeiro") == d.get("fim"),
            "ips": e.get("ips", [h["ip"]]), "svcs": hs,
        })
    # dispositivos do inventário que não apareceram nesta varredura
    if not parcial:
        for k, e in inv["dispositivos"].items():
            if k in seen or not e.get("ultimo"):
                continue
            mac = k if not k.startswith("IP:") else ""
            vend, private = vendor(mac)
            fake = {"ip": e.get("ip", ""), "mac": mac, "servicos": [], "netbios": e.get("nome_rede")}
            cat_auto, conf, ev = classify_device(fake, vend, private, None)
            devices.append({
                "chave": k, "ip": e.get("ip", ""), "mac": mac, "fabricante": tidy_vendor(vend) if vend else "",
                "fabricante_full": vend or "", "mac_privado": private,
                "nome": e.get("nome") or e.get("nome_rede") or "", "nome_auto": e.get("nome_rede") or "",
                "nome_rede": e.get("nome_rede") or "", "modelo": "",
                "cat": e.get("categoria") or cat_auto, "cat_auto": cat_auto, "manual": bool(e.get("categoria")),
                "confianca": conf, "evidencias": ev, "tag": "", "online": False, "ping": False,
                "notas": e.get("notas", ""), "primeiro": e.get("primeiro"), "ultimo": e.get("ultimo"),
                "novo": False, "ips": e.get("ips", []), "svcs": [],
            })
    ini = datetime.fromisoformat(d["inicio"])
    fim = datetime.fromisoformat(d["fim"]) if d.get("fim") else datetime.now()
    meta = {"rede": d["rede"], "data": ini.strftime("%d/%m/%Y %H:%M"), "inicio": d["inicio"], "fim": d.get("fim"),
            "duracao": f"{max(1, int((fim - ini).total_seconds() // 60))} min",
            "portas": d.get("portas_varridas", ""), "gw": gw, "eu": my_ip, "parcial": parcial,
            "oui": bool(_OUI) or load_oui() > 0, "gerado": datetime.now().strftime("%d/%m/%Y %H:%M")}
    return {"meta": meta,
            "devCats": [{"id": k, "nome": v[0], "icone": v[1]} for k, v in DEV_CATS.items()],
            "svcCats": [{"id": a, "nome": b, "icone": c} for a, b, c in SVC_CATS],
            "dispositivos": devices, "servicos": servs}


def render_static(payload, template=os.path.join(BASE, "app.html")):
    with open(template, encoding="utf-8") as f:
        tpl = f.read()
    data_js = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")
    return tpl.replace("/*__DADOS__*/null", data_js)


if __name__ == "__main__":
    import sys
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(DADOS, "varredura.json")
    dst = sys.argv[2] if len(sys.argv) > 2 else os.path.join(BASE, "mapa-da-rede.html")
    with open(src, encoding="utf-8") as f:
        d = json.load(f)
    inv = register_scan(d)
    p = build_payload(d, inv)
    with open(dst, "w", encoding="utf-8") as f:
        f.write(render_static(p))
    print(f"{dst}: {len(p['dispositivos'])} dispositivos, {len(p['servicos'])} serviços")
