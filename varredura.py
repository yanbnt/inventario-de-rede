"""
Varredura de rede: descobre hosts ativos, varre portas TCP e identifica serviços.
Uso direto (sem interface):  python varredura.py [--rede 192.168.1.0/24] [--portas 1-65535]   (sem --rede: detecta a rede local)
Normalmente é usado pelo app.py (interface gráfica).
"""
import argparse
import asyncio
import ctypes
import html
import ipaddress
import json
import re
import socket
import ssl
import struct
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

VERIFY_PORTS = [20, 21, 22, 23, 25, 53, 79, 80, 81, 88, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 515,
                548, 554, 587, 631, 636, 800, 808, 873, 993, 995, 1433, 1521, 1723, 1883, 2049, 3000, 3050, 3306,
                3389, 4443, 5000, 5060, 5061, 5432, 5672, 5900, 5985, 6379, 7000, 7070, 8000, 8001, 8008, 8009,
                8080, 8081, 8291, 8443, 8554, 8728, 8888, 9000, 9009, 9100, 9443, 10000, 27017, 34567, 37777, 62078]
DISCOVERY_PORTS = [21, 22, 23, 53, 80, 135, 139, 443, 445, 515, 554, 631, 3389,
                   5060, 8000, 8080, 8443, 9100, 37777]
# Portas de impressão "raw": qualquer dado enviado é impresso. Nunca enviar payload.
NO_PAYLOAD_PORTS = set(range(9100, 9110)) | {515, 2501}
# Conexões simultâneas por equipamento. Impressoras e câmeras perdem portas quando recebem uma rajada
# (as Ricoh deixavam de mostrar a 445). Quem não responde nada (firewall descartando) pode receber mais.
HOST_CONC = 8
HOST_CONC_MUDO = 32
# Portas que nenhum serviço usa. Se um equipamento "aceita" as duas, ele aceita conexão em qualquer porta
# (as impressoras Ricoh fazem isso e depois bloqueiam por alguns segundos): a lista de portas dele não vale,
# só as que responderem a um protocolo de verdade na identificação.
CANARY_PORTS = (47391, 61917)


import threading

NOWIN = 0x08000000 if __import__("os").name == "nt" else 0  # CREATE_NO_WINDOW

# Estado compartilhado com a interface (app.py lê isso enquanto a varredura roda)
STATE = {"fase": "ocioso", "rodando": False}
CANCEL = threading.Event()


def reset_state(rede, portas):
    STATE.clear()
    STATE.update(fase="descoberta", rodando=True, rede=rede, portas=portas, feito=0, total=0,
                 hosts=[], pinged=[], macs={}, abertas={}, log=[], erro=None,
                 inicio=datetime.now().isoformat(timespec="seconds"), fase_inicio=time.time())


def set_fase(f, total=0):
    STATE.update(fase=f, feito=0, total=total, fase_inicio=time.time())


def log(*a):
    msg = " ".join(str(x) for x in a)
    print(time.strftime("%H:%M:%S"), msg, flush=True)
    lg = STATE.setdefault("log", [])
    lg.append(time.strftime("%H:%M:%S") + " " + msg)
    del lg[:-60]


def own_mac(ip):
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command",
                              f"(Get-NetIPAddress -IPAddress {ip} | Get-NetAdapter).MacAddress"],
                             capture_output=True, timeout=15, creationflags=NOWIN).stdout.decode().strip()
        return out.replace("-", ":").upper() or None
    except Exception:
        return None


def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


# ---------------------------------------------------------------- descoberta
async def ping(ip, sem):
    async with sem:
        try:
            p = await asyncio.create_subprocess_exec(
                "ping", "-n", "1", "-w", "800", ip,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, creationflags=NOWIN)
            out, _ = await p.communicate()
            return b"TTL=" in out.upper()
        except Exception:
            return False


async def tcp_try(ip, port, timeout):
    """'open', 'closed' (recusou: RST) ou 'timeout' (nenhuma resposta)."""
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except asyncio.TimeoutError:
        return "timeout"
    except Exception:
        return "closed"
    try:
        w.close()
    except Exception:
        pass
    return "open"


async def tcp_open(ip, port, timeout):
    return await tcp_try(ip, port, timeout) == "open"


class Portao:
    """Limita as conexões simultâneas por equipamento. Um equipamento que só deixa as tentativas
    esgotarem o tempo (firewall descartando, típico de Windows) não está sobrecarregado: ganha mais vagas."""

    def __init__(self):
        self.sem, self.recusas, self.mudas, self.liberados = {}, {}, {}, set()

    def __call__(self, ip):
        s = self.sem.get(ip)
        if s is None:
            s = self.sem[ip] = asyncio.Semaphore(HOST_CONC)
        return s

    def anota(self, ip, r):
        if r == "timeout":
            self.mudas[ip] = self.mudas.get(ip, 0) + 1
        elif r == "closed":
            self.recusas[ip] = self.recusas.get(ip, 0) + 1
        if ip not in self.liberados and self.mudas.get(ip, 0) >= 48 and not self.recusas.get(ip):
            self.liberados.add(ip)
            for _ in range(HOST_CONC_MUDO - HOST_CONC):
                self.sem[ip].release()

    async def tentar(self, ip, port, timeout):
        async with self(ip):
            r = await tcp_try(ip, port, timeout)
        self.anota(ip, r)
        return r


def read_arp(net):
    """Tabela de vizinhos do Windows (IP -> MAC). Ignora entradas 'Unreachable'/'Incomplete': o `arp -a`
    mostrava equipamentos que já tinham saído da rede e eles eram contados como online."""
    try:
        ps = ("Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.State -notin "
              "'Unreachable','Incomplete' } | Select-Object IPAddress,LinkLayerAddress | ConvertTo-Json -Compress")
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, timeout=25,
                             creationflags=NOWIN)
        if out.returncode != 0:
            raise OSError(out.stderr[:200])
        txt = out.stdout.decode("utf-8", "replace").strip()
        data = json.loads(txt) if txt else []
        pares = [(x.get("IPAddress"), x.get("LinkLayerAddress") or "") for x in (data if isinstance(data, list) else [data])]
    except Exception:  # sem PowerShell/NetTCPIP: volta ao arp -a
        out = subprocess.run(["arp", "-a"], capture_output=True, creationflags=NOWIN).stdout.decode("cp850", "replace")
        pares = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", out)
    macs = {}
    for ip, mac in pares:
        mac = (mac or "").lower()
        if not re.fullmatch(r"[0-9a-f]{2}(-[0-9a-f]{2}){5}", mac) or mac in ("ff-ff-ff-ff-ff-ff", "00-00-00-00-00-00") \
                or mac.startswith("01-00-5e"):
            continue
        try:
            a = ipaddress.ip_address(ip)
            if a in net and a not in (net.network_address, net.broadcast_address):
                macs[ip] = mac.replace("-", ":").upper()
        except ValueError:
            pass
    return macs


def send_arp(ip):
    """Pergunta 'quem tem este IP?' agora (iphlpapi.SendARP, não exige administrador).
    Devolve o MAC se o equipamento respondeu, None se não respondeu, True se não dá para testar."""
    if NOWIN == 0:
        return True
    try:
        dst = struct.unpack("<I", socket.inet_aton(ip))[0]
        buf = (ctypes.c_ubyte * 8)()
        ln = ctypes.c_ulong(8)
        if ctypes.windll.iphlpapi.SendARP(dst, 0, buf, ctypes.byref(ln)) == 0 and ln.value >= 6:
            return ":".join(f"{b:02X}" for b in buf[:6])
        return None
    except Exception:
        return True


async def nbtstat(ip, sem):
    async with sem:
        try:
            p = await asyncio.create_subprocess_exec(
                "nbtstat", "-A", ip,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, creationflags=NOWIN)
            out, _ = await asyncio.wait_for(p.communicate(), 15)
            txt = out.decode("cp850", "replace")
            m = re.search(r"^\s*([^\s<]+)\s*<00>\s+(?:UNIQUE|EXCLUSIVO|Único|ÚNICO)", txt, re.M | re.I)
            if not m:
                m = re.search(r"^\s*([^\s<]+)\s*<20>", txt, re.M)
            return m.group(1) if m else None
        except Exception:
            return None


# ---------------------------------------------------------------- identificação
TLS_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
TLS_CTX.check_hostname = False
TLS_CTX.verify_mode = ssl.CERT_NONE
try:
    import warnings
    warnings.simplefilter("ignore", DeprecationWarning)
    TLS_CTX.minimum_version = ssl.TLSVersion.TLSv1
    TLS_CTX.set_ciphers("ALL:@SECLEVEL=0")
except Exception:
    pass


async def read_some(r, timeout, limit=65536):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    data = b""
    while len(data) < limit:
        rem = end - loop.time()
        if rem <= 0:
            break
        try:
            chunk = await asyncio.wait_for(r.read(8192), rem)
        except Exception:
            break
        if not chunk:
            break
        data += chunk
    return data


def clean(b, n=200):
    t = b.decode("utf-8", "replace")
    t = "".join(c if c.isprintable() else " " for c in t)
    return re.sub(r"\s+", " ", t).strip()[:n]


def decode_body(body, ctype):
    m = re.search(r"charset=([\w-]+)", ctype or "", re.I) or \
        re.search(rb"charset=[\"']?([\w-]+)", body[:4096], re.I)
    cs = m.group(1) if m else "utf-8"
    if isinstance(cs, bytes):
        cs = cs.decode()
    try:
        return body.decode(cs, "replace")
    except LookupError:
        return body.decode("utf-8", "replace")


def parse_http(data):
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    hdr = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        hdr[k.strip().lower()] = v.strip()
    text = decode_body(body, hdr.get("content-type"))
    info = {"status": lines[0][:80]}
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if m:
        t = re.sub(r"\s+", " ", html.unescape(m.group(1))).strip()
        if t:
            info["title"] = t[:150]
    if hdr.get("server"):
        info["server"] = hdr["server"][:100]
    if hdr.get("location"):
        info["location"] = hdr["location"][:200]
    if hdr.get("www-authenticate"):
        info["auth"] = hdr["www-authenticate"][:120]
    if "location" not in info:
        m = re.search(r"(?:http-equiv=[\"']?refresh[^>]*url=|location(?:\.href)?\s*=\s*)[\"']?([^\"'>;\s]+)", text, re.I)
        if m:
            info["location"] = m.group(1)[:200]
    # pistas de fabricante no corpo
    m = re.search(r"\b(Hikvision|Dahua|Intelbras|MikroTik|RouterOS|UniFi|Ubiquiti|TP-Link|Huawei|ZTE|Fortinet|FortiGate|pfSense|OPNsense|Sophos|"
                  r"Grandstream|Yealink|Synology|QNAP|Proxmox|VMware|ESXi|iDRAC|iLO|Zabbix|Grafana|GLPI|Epson|Brother|Kyocera|Ricoh|"
                  r"Lexmark|Xerox|Canon|Samsung|HP LaserJet|HP Color|OfficeJet|Aruba|Cisco|Juniper|D-Link|Mercusys|Tenda|Ruijie|"
                  r"Elsys|Furukawa|Datacom|Control iD|ControlID|Henry|Topdata|Hikcentral|Ezviz|Jellyfin|Plex|Portainer)\b", text, re.I)
    if m:
        info["hint"] = m.group(1)
    return info


def http_req(ip, port):
    return (f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: Mozilla/5.0 (scanner-de-rede)\r\n"
            f"Accept: text/html,*/*\r\nConnection: close\r\n\r\n").encode()


async def probe(ip, port, sem):
    info = {"port": port}
    async with sem:
        # 1) banner passivo (SSH, FTP, SMTP, VNC, MySQL...)
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), 3)
            banner = await read_some(r, 1.5, 4096)
            w.close()
        except Exception:
            return info
        if banner:
            if banner.startswith(b"HTTP/"):
                info.update(parse_http(banner)); info["proto"] = "http"
            else:
                info["banner"] = clean(banner)
            return info
        if port in NO_PAYLOAD_PORTS:
            info["proto"] = "raw-print" if port != 515 else "lpd"
            return info
        # 2) TLS + HTTP
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=TLS_CTX), 4)
            try:
                w.write(http_req(ip, port))
                data = await read_some(r, 5)
            finally:
                w.close()
            info["tls"] = True
            if data.startswith(b"HTTP/"):
                info.update(parse_http(data)); info["proto"] = "https"
            elif data:
                info["banner"] = clean(data); info["proto"] = "tls"
            else:
                info["proto"] = "tls"
            return info
        except Exception:
            pass
        # 3) HTTP puro
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), 3)
            try:
                w.write(http_req(ip, port))
                data = await read_some(r, 5)
            finally:
                w.close()
            if data.startswith(b"HTTP/"):
                info.update(parse_http(data)); info["proto"] = "http"
            elif data.startswith(b"RTSP/"):
                info["proto"] = "rtsp"; info["banner"] = clean(data)
            elif data:
                info["banner"] = clean(data)
            else:
                # 4) RTSP (câmeras/DVR)
                r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), 3)
                try:
                    w.write(f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
                    data = await read_some(r, 3, 4096)
                finally:
                    w.close()
                if data.startswith(b"RTSP/"):
                    info["proto"] = "rtsp"
                    m = re.search(rb"Server:\s*([^\r\n]+)", data)
                    if m:
                        info["server"] = clean(m.group(1), 100)
                elif data:
                    info["banner"] = clean(data)
        except Exception:
            pass
    return info


# ---------------------------------------------------------------- principal
def local_ip_in(net):
    """IP deste computador dentro de `net` (o PC pode ter vários adaptadores)."""
    cands = []
    try:
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sk.connect(("8.8.8.8", 80))  # não envia pacotes
        cands.append(sk.getsockname()[0]); sk.close()
    except Exception:
        pass
    try:
        cands += socket.gethostbyname_ex(socket.gethostname())[2]
    except Exception:
        pass
    for ip in cands:
        try:
            if ipaddress.ip_address(ip) in net:
                return ip
        except ValueError:
            pass
    return cands[0] if cands else None


# Descoberta de APs/rádios Intelbras (protocolo do "Reset Tool", herdado da Wilibox/Deliberant):
# consulta multicast 233.89.188.1:10001 com 4 bytes zerados = "quem é você?". Cada equipamento responde
# ver(1) cmd(1) mac(6) ip(4) tamanho(4, big-endian) "MODELO.vFIRMWARE". Só consulta — nunca envia reset.
WILI_GRUPO, WILI_PORTA = "233.89.188.1", 10001


def intelbras_discovery(local_ip, net, espera=2.5):
    achados = {}
    if not local_ip:
        return achados
    try:
        # sem bind(): o Windows abre a porta só no envio e libera a resposta unicast ao multicast
        # (regra padrão do firewall, 3 s) — não dispara o aviso "Permitir acesso" do Firewall
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sk.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        sk.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sk.settimeout(0.25)
    except OSError:
        return achados
    with sk:
        fim = time.time() + espera
        for _ in range(2):  # repete uma vez: UDP pode perder pacote
            try:
                sk.sendto(bytes(4), (WILI_GRUPO, WILI_PORTA))
            except OSError:
                return achados
        while time.time() < fim:
            try:
                d, (ip, _) = sk.recvfrom(1500)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                if len(d) < 16 or d[1] != 0 or ipaddress.ip_address(ip) not in net:
                    continue
                n = int.from_bytes(d[12:16], "big")
                txt = d[16:16 + max(0, min(n, 200))].decode("utf-8", "replace").strip("\x00 ")
            except ValueError:
                continue
            modelo, _, fw = txt.rpartition(".v") if ".v" in txt else (txt, "", "")
            achados[ip] = {"protocolo": "intelbras", "mac": ":".join(f"{b:02X}" for b in d[2:8]),
                           "modelo": modelo.strip(), "firmware": fw.strip()}
    return achados


async def main(a):
    net = ipaddress.ip_network(a.rede, strict=False)
    all_ips = [str(h) for h in net.hosts()]
    t0 = datetime.now()
    loop = asyncio.get_running_loop()
    # dispositivos que derrubam a conexão (RST) geram avisos inofensivos do asyncio no Windows
    loop.set_exception_handler(lambda lp, ctx: None if isinstance(ctx.get("exception"), (ConnectionError, OSError))
                               else lp.default_exception_handler(ctx))
    reset_state(str(net), a.portas)
    CANCEL.clear()
    log(f"Rede {net} — {len(all_ips)} endereços")

    # 1) descoberta: ping + portas comuns + tabela ARP
    set_fase("descoberta", len(all_ips) * (1 + len(DISCOVERY_PORTS) + len(CANARY_PORTS)))
    sem = asyncio.Semaphore(64)

    async def ping_c(ip):
        ok = await ping(ip, sem)
        STATE["feito"] += 1
        return ok
    my_ip = local_ip_in(net)
    desc_task = asyncio.ensure_future(asyncio.to_thread(intelbras_discovery, my_ip, net))
    pings = await asyncio.gather(*(ping_c(ip) for ip in all_ips))
    descoberta = await desc_task
    STATE["descoberta"] = descoberta
    if descoberta:
        log(f"APs/rádios Intelbras que se identificaram: {len(descoberta)}")
    pinged = {ip for ip, ok in zip(all_ips, pings) if ok}
    STATE["pinged"] = sorted(pinged)
    log(f"Responderam ao ping: {len(pinged)}")
    sem2 = asyncio.Semaphore(1500)
    gate = Portao()

    async def disc(ip, port):
        async with sem2:
            ok = await gate.tentar(ip, port, 0.8) == "open"
            STATE["feito"] += 1
            return (ip, port) if ok else None
    # as portas-isca vão primeiro (o equipamento que bloqueia depois de algumas conexões ainda responde a elas);
    # ordem porta -> IP: espalha as tentativas em vez de despejar todas as portas no mesmo equipamento
    todos = [x for x in await asyncio.gather(*(disc(ip, p) for p in CANARY_PORTS + tuple(DISCOVERY_PORTS)
                                               for ip in all_ips)) if x]
    iscas = {}
    for ip, p in todos:
        if p in CANARY_PORTS:
            iscas[ip] = iscas.get(ip, 0) + 1
    aceita_tudo = {ip for ip, n in iscas.items() if n == len(CANARY_PORTS)}
    STATE["aceita_tudo"] = sorted(aceita_tudo)
    if aceita_tudo:
        log("Aceitam conexão em qualquer porta (só valem as portas que responderem): " + ", ".join(sorted(aceita_tudo)))
    tcp_hits = [(ip, p) for ip, p in todos if p not in CANARY_PORTS]
    tcp_alive = {ip for ip, _ in todos}
    macs = read_arp(net)
    # quem apareceu só na tabela ARP precisa responder a um ARP agora (a entrada pode ser antiga)
    so_arp = sorted(set(macs) - pinged - tcp_alive - set(descoberta))
    if so_arp:
        resp = await asyncio.gather(*(asyncio.to_thread(send_arp, ip) for ip in so_arp))
        sumiram = [ip for ip, r in zip(so_arp, resp) if r is None]
        for ip in sumiram:
            macs.pop(ip, None)
        log(f"Só na tabela ARP: {len(so_arp)}, confirmados agora: {len(so_arp) - len(sumiram)}"
            + (f" (fora da rede: {', '.join(sumiram)})" if sumiram else ""))
    for ip, info in descoberta.items():
        macs.setdefault(ip, info["mac"])
    hosts = sorted(pinged | tcp_alive | set(macs) | set(descoberta), key=lambda s: ipaddress.ip_address(s))
    if a.hosts:
        hosts = [h for h in hosts if h in a.hosts.split(",")] or a.hosts.split(",")
    if my_ip in hosts and my_ip not in macs:
        m = own_mac(my_ip)
        if m:
            macs[my_ip] = m
    open_ports = {h: [] for h in hosts}
    for ip, p in tcp_hits:  # portas já confirmadas na descoberta
        if ip in open_ports and p not in open_ports[ip]:
            open_ports[ip].append(p)
    STATE.update(hosts=hosts, macs=macs, abertas=open_ports)
    log(f"Hosts ativos: {len(hosts)} (ping {len(pinged)}, tcp {len(tcp_alive)}, arp {len(macs)})")

    # 2) varredura de portas
    ports = parse_ports(a.portas)
    set_fase("portas", len(ports) * len(hosts))

    def gen():
        for p in ports:
            for h in hosts:
                yield h, p
    it = gen()

    async def worker(n):
        await asyncio.sleep(n * 0.002)  # entrada gradual: evita a rajada inicial que estoura o tempo limite
        for h, p in it:
            if CANCEL.is_set():
                return
            if await gate.tentar(h, p, a.timeout) == "open" and p not in open_ports[h]:
                open_ports[h].append(p)
            STATE["feito"] += 1

    async def progress():
        while True:
            await asyncio.sleep(20)
            log(f"progresso {STATE['feito']}/{STATE['total']} ({STATE['feito'] * 100 / max(STATE['total'], 1):.1f}%) — "
                f"portas abertas: {sum(map(len, open_ports.values()))}")
    pt = asyncio.create_task(progress())
    await asyncio.gather(*(worker(n) for n in range(a.conc)))
    pt.cancel()
    cancelado = CANCEL.is_set()

    # 2b) reconferência das portas mais comuns com tempo limite maior (pega o que escapou sob carga)
    if not cancelado:
        common = [p for p in VERIFY_PORTS if p in set(ports)]
        set_fase("portas", len(common) * len(hosts))
        vsem = asyncio.Semaphore(400)
        antes = sum(map(len, open_ports.values()))

        async def verify(h, p):
            async with vsem:
                if p not in open_ports[h] and not CANCEL.is_set():
                    for _ in range(2):  # 2 tentativas: equipamento ocupado pode perder a primeira
                        if await gate.tentar(h, p, 1.5) == "open":
                            open_ports[h].append(p)
                            break
                STATE["feito"] += 1
        await asyncio.gather(*(verify(h, p) for p in common for h in hosts))
        extra = sum(map(len, open_ports.values())) - antes
        if extra:
            log(f"Reconferência das portas comuns: +{extra} portas")
    log(("Varredura interrompida" if cancelado else "Varredura concluída") +
        f": {sum(map(len, open_ports.values()))} portas abertas")

    # 3) identificação dos serviços
    jobs = [(h, p) for h in hosts for p in sorted(open_ports[h])]
    set_fase("identificacao", len(jobs))
    psem = asyncio.Semaphore(48)

    async def probe_c(h, p):
        r = await probe(h, p, psem)
        STATE["feito"] += 1
        return r
    infos = await asyncio.gather(*(probe_c(h, p) for h, p in jobs))
    by_host = {h: [] for h in hosts}
    for (h, _), inf in zip(jobs, infos):
        by_host[h].append(inf)
    log("Identificação concluída")

    # 4) nomes (DNS reverso + NetBIOS)
    set_fase("nomes", len(hosts) * 2)
    loop = asyncio.get_running_loop()
    ex = ThreadPoolExecutor(64)

    async def rdns(ip):
        try:
            return (await asyncio.wait_for(loop.run_in_executor(ex, socket.gethostbyaddr, ip), 6))[0]
        except Exception:
            return None
        finally:
            STATE["feito"] += 1
    nsem = asyncio.Semaphore(32)

    async def nb_c(ip):
        r = await nbtstat(ip, nsem)
        STATE["feito"] += 1
        return r
    names = await asyncio.gather(*(rdns(h) for h in hosts))
    nb = await asyncio.gather(*(nb_c(h) for h in hosts))
    for k, v in read_arp(net).items():
        macs.setdefault(k, v)

    result = {
        "rede": str(net), "inicio": t0.isoformat(timespec="seconds"),
        "fim": datetime.now().isoformat(timespec="seconds"),
        "portas_varridas": a.portas + (" (interrompida)" if cancelado else ""),
        "hosts": [{
            "ip": h, "mac": macs.get(h), "hostname": n if n and n != h else None,
            "netbios": b, "ping": h in pinged, "servicos": by_host[h],
            **({"descoberta": descoberta[h]} if h in descoberta else {}),
            **({"aceita_tudo": True} if h in aceita_tudo else {}),
        } for h, n, b in zip(hosts, names, nb)],
    }
    with open(a.saida, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=1)
    STATE.update(fase="concluida", rodando=False, resultado=result)
    log(f"Resultado salvo em {a.saida}")
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--rede", default="", help="CIDR; vazio = rede /24 deste computador")
    ap.add_argument("--portas", default="1-65535")
    ap.add_argument("--saida", default="dados/varredura.json")
    ap.add_argument("--conc", type=int, default=2000)
    ap.add_argument("--timeout", type=float, default=0.5)
    ap.add_argument("--hosts", default="", help="restringe a IPs específicos (separados por vírgula)")
    args = ap.parse_args()
    if not args.rede:
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sk.connect(("8.8.8.8", 80))  # não envia pacotes; só descobre o IP local
        args.rede = str(ipaddress.ip_network(sk.getsockname()[0] + "/24", strict=False))
        sk.close()
    asyncio.run(main(args))
