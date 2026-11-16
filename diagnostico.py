"""
Diagnóstico da rede: testes de conexão e motor de achados do relatório.

Testes (nesta ordem, para o teste de velocidade não atrapalhar as latências):
    adaptador -> gateway -> internet -> DNS -> MTU -> rota -> velocidade
Roda numa thread iniciada pelo app.py, com STATE e CANCEL no mesmo padrão do varredura.py.
Nada aqui exige administrador: ICMP pela API do Windows (iphlpapi), DNS montado à mão por UDP.
O único serviço externo usado é o teste de velocidade (speed.cloudflare.com), e só se estiver ligado.
"""
import ctypes
import http.client
import ipaddress
import json
import os
import random
import re
import socket
import statistics
import struct
import subprocess
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import identificar as I

DIAG_JSON = os.path.join(I.DADOS, "diagnostico.json")
CONFIG_JSON = os.path.join(I.DADOS, "config.json")
CONFIG_PADRAO = {
    "local": "", "autor": "", "plano_down_mbps": None, "plano_up_mbps": None,
    "teste_velocidade": True, "dns_extra": ["8.8.8.8", "1.1.1.1"], "pendencias_extra": "",
}
ALVOS_INTERNET = ["8.8.8.8", "1.1.1.1"]
DOMINIOS_DNS = ["google.com", "microsoft.com", "intelbras.com.br", "cloudflare.com"]
VEL_HOST = "speed.cloudflare.com"
VEL_DOWN_BYTES, VEL_DOWN_RODADAS = 25_000_000, 3
VEL_UP_BYTES, VEL_UP_RODADAS = 10_000_000, 2
UA = "Mozilla/5.0 (inventario-rede)"

FASES = [("varredura", "Varredura rápida"), ("adaptador", "Placa de rede"), ("gateway", "Roteador"),
         ("internet", "Internet"), ("dns", "DNS"), ("mtu", "MTU"), ("rota", "Rota"), ("velocidade", "Velocidade")]

STATE = {"fase": "ocioso", "rodando": False}
CANCEL = threading.Event()


def reset_state(etapas):
    STATE.clear()
    STATE.update(fase=etapas[0], rodando=True, feito=0, total=0, log=[], erro=None, etapas=etapas,
                 inicio=datetime.now().isoformat(timespec="seconds"), fase_inicio=time.time())


def set_fase(f, total=0):
    STATE.update(fase=f, feito=0, total=total, fase_inicio=time.time())


def log(*a):
    msg = " ".join(str(x) for x in a)
    print(time.strftime("%H:%M:%S"), "[diag]", msg, flush=True)
    lg = STATE.setdefault("log", [])
    lg.append(time.strftime("%H:%M:%S") + " " + msg)
    del lg[:-60]


# ------------------------------------------------------------------ configuração
def load_config():
    c = dict(CONFIG_PADRAO)
    try:
        with open(CONFIG_JSON, encoding="utf-8") as f:
            c.update({k: v for k, v in json.load(f).items() if k in CONFIG_PADRAO})
    except Exception:
        pass
    return c


def _num(v):
    try:
        v = float(str(v).replace(",", "."))
        return round(v, 1) if 0 < v < 100000 else None
    except (TypeError, ValueError):
        return None


def save_config(novo):
    c = load_config()
    if "local" in novo:
        c["local"] = str(novo["local"] or "").strip()[:80]
    if "autor" in novo:
        c["autor"] = str(novo["autor"] or "").strip()[:80]
    for k in ("plano_down_mbps", "plano_up_mbps"):
        if k in novo:
            c[k] = _num(novo[k])
    if "teste_velocidade" in novo:
        c["teste_velocidade"] = bool(novo["teste_velocidade"])
    if "dns_extra" in novo:
        lst = novo["dns_extra"]
        if isinstance(lst, str):
            lst = re.split(r"[\s,;]+", lst)
        ok = []
        for x in lst or []:
            try:
                if ipaddress.IPv4Address(str(x).strip()) and str(x).strip() not in ok:
                    ok.append(str(x).strip())
            except ValueError:
                pass
        c["dns_extra"] = ok[:4]
    if "pendencias_extra" in novo:
        c["pendencias_extra"] = str(novo["pendencias_extra"] or "")[:2000]
    tmp = CONFIG_JSON + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(c, f, ensure_ascii=False, indent=1)
    os.replace(tmp, CONFIG_JSON)
    return c


def load_diag():
    try:
        with open(DIAG_JSON, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_diag(res):
    ant = load_diag() or {}
    hist = ant.get("historico", [])
    if ant.get("inicio"):  # guarda um resumo do anterior (sem as amostras)
        hist.append(_resumo_hist(ant))
    res["historico"] = hist[-20:]
    tmp = DIAG_JSON + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=1)
    os.replace(tmp, DIAG_JSON)


def _resumo_hist(d):
    g = d.get("gateway") or {}
    v = d.get("velocidade") or {}
    return {"inicio": d.get("inicio"), "rede": d.get("rede"),
            "gw_perda": g.get("perda_pct"), "gw_media_ms": g.get("media_ms"),
            "down_mbps": _mediana(v.get("download_mbps")), "up_mbps": _mediana(v.get("upload_mbps")),
            "achados": [a.get("id") for a in d.get("achados", [])]}


def _mediana(lst):
    lst = [x for x in (lst or []) if isinstance(x, (int, float))]
    return round(statistics.median(lst), 1) if lst else None


# ------------------------------------------------------------------ ICMP (iphlpapi, sem administrador)
class IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte),
                ("OptionsSize", ctypes.c_ubyte), ("OptionsData", ctypes.c_void_p)]


class ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [("Address", ctypes.c_ulong), ("Status", ctypes.c_ulong), ("RoundTripTime", ctypes.c_ulong),
                ("DataSize", ctypes.c_ushort), ("Reserved", ctypes.c_ushort), ("Data", ctypes.c_void_p),
                ("Options", IP_OPTION_INFORMATION)]


IP_SUCCESS, IP_PACKET_TOO_BIG, IP_REQ_TIMED_OUT, IP_TTL_EXPIRED_TRANSIT = 0, 11009, 11010, 11013
_ICMP = None


def _icmp():
    global _ICMP
    if _ICMP is None:
        lib = ctypes.WinDLL("iphlpapi", use_last_error=True)
        lib.IcmpCreateFile.restype = ctypes.c_void_p
        lib.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
        lib.IcmpSendEcho.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ushort,
                                     ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
        lib.IcmpSendEcho.restype = ctypes.c_ulong
        _ICMP = lib
    return _ICMP


class Pinger:
    """Um handle ICMP por thread. ping() devolve (status, rtt_ms, endereço que respondeu)."""

    def __init__(self):
        self.lib = _icmp()
        self.h = self.lib.IcmpCreateFile()

    def close(self):
        if self.h:
            self.lib.IcmpCloseHandle(self.h)
            self.h = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def ping(self, ip, timeout_ms=1000, size=32, ttl=128, df=False):
        dst = struct.unpack("<I", socket.inet_aton(ip))[0]
        data = ctypes.create_string_buffer(b"a" * size, size)
        opt = IP_OPTION_INFORMATION(ttl, 0, 2 if df else 0, 0, None)  # 2 = IP_FLAG_DF (não fragmentar)
        rsize = ctypes.sizeof(ICMP_ECHO_REPLY) + size + 64
        buf = ctypes.create_string_buffer(rsize)
        n = self.lib.IcmpSendEcho(self.h, dst, data, size, ctypes.byref(opt), buf, rsize, timeout_ms)
        r = ICMP_ECHO_REPLY.from_buffer(buf)
        addr = socket.inet_ntoa(struct.pack("<I", r.Address)) if r.Address else None
        if n == 0:
            st = ctypes.get_last_error() or r.Status or IP_REQ_TIMED_OUT
            return st, None, addr
        return r.Status, r.RoundTripTime, addr


def _pct(lst, q):
    s = sorted(lst)
    if not s:
        return None
    k = (len(s) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return round(s[lo] + (s[hi] - s[lo]) * (k - lo), 1)


def resumo_ping(alvo, am):
    ok = [x for x in am if x >= 0]
    n = len(am)
    return {"alvo": alvo, "enviados": n, "perdidos": n - len(ok),
            "perda_pct": round(100 * (n - len(ok)) / n, 1) if n else None,
            "media_ms": round(statistics.mean(ok), 2) if ok else None,
            "p95_ms": _pct(ok, .95), "p99_ms": _pct(ok, .99),
            "min_ms": min(ok) if ok else None, "max_ms": max(ok) if ok else None, "amostras": am}


def serie_ping(alvo, n, intervalo=0.02, timeout_ms=1000):
    am = []
    with Pinger() as p:
        for _ in range(n):
            if CANCEL.is_set():
                break
            t0 = time.perf_counter()
            st, rtt, _ = p.ping(alvo, timeout_ms)
            am.append(int(rtt) if st == IP_SUCCESS and rtt is not None else -1)
            STATE["feito"] += 1
            resto = intervalo - (time.perf_counter() - t0)
            if resto > 0:
                time.sleep(resto)
    return resumo_ping(alvo, am)


# ------------------------------------------------------------------ adaptador
def adaptador(ip):
    ip = str(ipaddress.IPv4Address(ip))  # validado antes de entrar no comando
    ps = ("$i = Get-NetIPAddress -IPAddress '" + ip + "' -ErrorAction Stop | Select-Object -First 1; "
          "$a = Get-NetAdapter -InterfaceIndex $i.InterfaceIndex -ErrorAction Stop; "
          "$s = Get-NetAdapterStatistics -Name $a.Name -ErrorAction SilentlyContinue; "
          "$d = (Get-DnsClientServerAddress -InterfaceIndex $i.InterfaceIndex -AddressFamily IPv4 "
          "-ErrorAction SilentlyContinue).ServerAddresses; "
          "[pscustomobject]@{ Nome=$a.Name; Descricao=$a.InterfaceDescription; Fisico=\"$($a.PhysicalMediaType)\"; "
          "Mac=$a.MacAddress; Bps=[double]$a.ReceiveLinkSpeed; BpsTx=[double]$a.TransmitLinkSpeed; "
          "ErrRx=[double]$s.ReceivedPacketErrors; ErrTx=[double]$s.OutboundPacketErrors; "
          "Desc=[double]$s.ReceivedDiscardedPackets; Dns=@($d) } | ConvertTo-Json -Compress")
    out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, timeout=30,
                         creationflags=I.NOWIN)
    x = json.loads(out.stdout.decode("utf-8", "replace") or "{}")
    wifi = bool(re.search(r"802\.11|wireless|wi-?fi|wlan", f"{x.get('Fisico')} {x.get('Descricao')}", re.I))
    bps = max(x.get("Bps") or 0, x.get("BpsTx") or 0)
    res = {"nome": x.get("Nome"), "descricao": x.get("Descricao"), "tipo": "wifi" if wifi else "cabo",
           "velocidade_mbps": round(bps / 1e6) if bps else None,
           "erros_rx": int(x.get("ErrRx") or 0), "erros_tx": int(x.get("ErrTx") or 0),
           "descartes": int(x.get("Desc") or 0), "dns": [d for d in (x.get("Dns") or []) if d], "wifi": None}
    if wifi:
        res["wifi"] = wifi_info(x.get("Nome") or "")
    return res


def wifi_info(alias):
    try:
        txt = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, timeout=15,
                             creationflags=I.NOWIN).stdout.decode("cp850", "replace")
    except Exception:
        return None
    blocos = re.split(r"\r?\n\s*\r?\n", txt)
    bloco = next((b for b in blocos if re.search(r"^\s*(Nome|Name)\s*:\s*" + re.escape(alias) + r"\s*$", b, re.M | re.I)),
                 next((b for b in blocos if re.search(r"^\s*SSID\s*:", b, re.M)), ""))

    def campo(rx, conv=str):
        m = re.search(rx, bloco, re.M | re.I)
        if not m:
            return None
        try:
            return conv(m.group(1).strip().replace(",", "."))
        except ValueError:
            return None
    return {"ssid": campo(r"^\s*SSID\s*:\s*(.+)$"), "bssid": campo(r"^\s*BSSID\s*:\s*(.+)$"),
            "canal": campo(r"^\s*(?:Canal|Channel)\s*:\s*(\d+)", int),
            "sinal_pct": campo(r"^\s*(?:Sinal|Signal)\s*:\s*(\d+)\s*%", int),
            "rx_mbps": campo(r"^\s*(?:Taxa de recep\S*|Receive rate)[^:]*:\s*([\d.,]+)", float),
            "tx_mbps": campo(r"^\s*(?:Taxa de transmiss\S*|Transmit rate)[^:]*:\s*([\d.,]+)", float)}


# ------------------------------------------------------------------ DNS (consulta A montada à mão)
def dns_consulta(servidor, nome, timeout=2.0):
    """Tempo em ms da resposta com pelo menos um endereço, ou None se falhou."""
    tid = random.randrange(65536)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode("ascii") for p in nome.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        t0 = time.perf_counter()
        try:
            s.sendto(q, (servidor, 53))
            while True:
                data, _ = s.recvfrom(4096)
                if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == tid:
                    break
        except OSError:
            return None
        ms = (time.perf_counter() - t0) * 1000
    flags, _, an = struct.unpack(">HHH", data[2:8])
    return round(ms, 1) if flags & 0xF == 0 and an > 0 else None


def teste_dns(servidores):
    res = []
    for sv in servidores:
        tempos = []
        for dom in DOMINIOS_DNS:
            if CANCEL.is_set():
                break
            tempos.append(dns_consulta(sv, dom))
            STATE["feito"] += 1
        ok = [t for t in tempos if t is not None]
        res.append({"servidor": sv, "consultas": len(tempos), "falhas": len(tempos) - len(ok),
                    "mediana_ms": round(statistics.median(ok), 1) if ok else None,
                    "max_ms": max(ok) if ok else None, "tempos": tempos})
    return res


# ------------------------------------------------------------------ MTU (ICMP com "não fragmentar")
def teste_mtu(alvo="8.8.8.8"):
    """Busca binária do maior pacote que passa com DF. Cada tamanho tem 3 tentativas: passou se 1 voltou
    (com 1 tentativa só, uma perda isolada derruba a busca)."""
    falhas = []

    def passa(payload):
        sts = []
        with Pinger() as p:
            for _ in range(3):
                st, _, _ = p.ping(alvo, 1000, payload, df=True)
                sts.append(st)
                if st == IP_SUCCESS:
                    STATE["feito"] += 1
                    return True
        falhas.extend(sts)
        STATE["feito"] += 1
        return False
    if passa(1472):
        return {"caminho": 1500, "pmtud_ok": True, "alvo": alvo}
    lo, hi = 1200, 1471
    if not passa(lo):
        return {"caminho": None, "pmtud_ok": IP_PACKET_TOO_BIG in falhas, "alvo": alvo,
                "erro": "nem pacotes de 1228 bytes passaram"}
    while lo < hi and not CANCEL.is_set():
        mid = (lo + hi + 1) // 2
        if passa(mid):
            lo = mid
        else:
            hi = mid - 1
    # PMTUD funciona se o caminho avisou "precisa fragmentar" em vez de descartar em silêncio
    return {"caminho": lo + 28, "pmtud_ok": IP_PACKET_TOO_BIG in falhas, "alvo": alvo}


# ------------------------------------------------------------------ rota (ICMP com TTL crescente)
def teste_rota(alvo="8.8.8.8", max_saltos=15):
    def salto(ttl):
        with Pinger() as p:
            for _ in range(2):
                st, rtt, addr = p.ping(alvo, 1000, 32, ttl=ttl)
                if addr and addr != "0.0.0.0" and st in (IP_SUCCESS, IP_TTL_EXPIRED_TRANSIT, 11012, 11013):
                    STATE["feito"] += 1
                    return {"n": ttl, "ip": addr, "ms": rtt, "fim": st == IP_SUCCESS}
        STATE["feito"] += 1
        return {"n": ttl, "ip": None, "ms": None, "fim": False}
    with ThreadPoolExecutor(max_saltos) as ex:
        hops = list(ex.map(salto, range(1, max_saltos + 1)))
    out = []
    for h in hops:
        out.append(h)
        if h["fim"]:
            break
    chegou = bool(out and out[-1]["fim"])
    return {"alvo": alvo, "saltos": len(out) if chegou else None, "chegou": chegou, "hops": out}


# ------------------------------------------------------------------ velocidade
def teste_velocidade():
    res = {"servidor": VEL_HOST, "download_mbps": [], "upload_mbps": [], "pulado": False, "erro": None,
           "bytes_down": VEL_DOWN_BYTES, "bytes_up": VEL_UP_BYTES}
    try:
        for _ in range(VEL_DOWN_RODADAS):
            if CANCEL.is_set():
                break
            req = urllib.request.Request(f"https://{VEL_HOST}/__down?bytes={VEL_DOWN_BYTES}", headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=60) as r:
                t0, total = time.perf_counter(), 0
                while not CANCEL.is_set():
                    ch = r.read(262144)
                    if not ch:
                        break
                    total += len(ch)
                    if time.perf_counter() - t0 > 60:
                        break
                dt = time.perf_counter() - t0
            if total and dt > 0 and not CANCEL.is_set():
                res["download_mbps"].append(round(total * 8 / dt / 1e6, 1))
                log(f"Download: {res['download_mbps'][-1]} Mbps")
            STATE["feito"] += 1
        corpo = os.urandom(VEL_UP_BYTES)
        for _ in range(VEL_UP_RODADAS):
            if CANCEL.is_set():
                break
            c = http.client.HTTPSConnection(VEL_HOST, timeout=60)
            try:
                c.connect()
                t0 = time.perf_counter()
                c.putrequest("POST", "/__up")
                c.putheader("User-Agent", UA)
                c.putheader("Content-Type", "application/octet-stream")
                c.putheader("Content-Length", str(len(corpo)))
                c.endheaders()
                for i in range(0, len(corpo), 262144):
                    if CANCEL.is_set() or time.perf_counter() - t0 > 60:
                        break
                    c.send(corpo[i:i + 262144])
                else:
                    r = c.getresponse()
                    r.read()
                    dt = time.perf_counter() - t0
                    res["upload_mbps"].append(round(len(corpo) * 8 / dt / 1e6, 1))
                    log(f"Upload: {res['upload_mbps'][-1]} Mbps")
            finally:
                c.close()
            STATE["feito"] += 1
    except Exception as e:
        res["erro"] = str(e)[:200]
        log(f"Teste de velocidade falhou: {e}")
    return res


# ------------------------------------------------------------------ execução
def etapas(cfg, com_varredura):
    return [f for f, _ in FASES if (f != "velocidade" or cfg.get("teste_velocidade"))
            and (f != "varredura" or com_varredura)]


def executar(rede, cfg=None, preparado=False):
    """Roda todos os testes e salva dados/diagnostico.json. `rede` = CIDR da varredura.
    preparado=True: quem chamou já fez reset_state()/CANCEL.clear() (o app.py, que pode rodar uma varredura antes)."""
    import varredura as V
    cfg = cfg or load_config()
    if not preparado:
        reset_state(etapas(cfg, False))
        CANCEL.clear()
    net = ipaddress.ip_network(rede, strict=False)
    eu = V.local_ip_in(net)
    _, gw = I.local_info(str(net))
    log(f"Diagnóstico da rede {net} a partir de {eu} (gateway {gw or 'não encontrado'})")
    res = {"inicio": datetime.now().isoformat(timespec="seconds"), "fim": None, "rede": str(net),
           "eu": eu, "gw": gw, "cancelado": False}

    def fase(nome, total, fn, *a):
        if CANCEL.is_set():
            return None
        set_fase(nome, total)
        try:
            return fn(*a)
        except Exception as e:
            log(f"{nome}: falhou ({e})")
            return {"erro": str(e)[:200]}

    res["adaptador"] = fase("adaptador", 1, adaptador, eu)
    a = res["adaptador"] or {}
    if a.get("nome"):
        log(f"Placa: {a['nome']} ({a.get('tipo')}, {a.get('velocidade_mbps')} Mbps)")
    if gw:
        res["gateway"] = fase("gateway", 250, serie_ping, gw, 250, 0.02)
        g = res["gateway"] or {}
        if g.get("enviados"):
            log(f"Roteador: {g['perdidos']} perdidos de {g['enviados']}, média {g['media_ms']} ms, máx {g['max_ms']} ms")
    else:
        res["gateway"] = None
        log("Sem gateway nesta rede: teste do roteador pulado")
    res["internet"] = fase("internet", 50 * len(ALVOS_INTERNET),
                           lambda: [serie_ping(x, 50, 0.02) for x in ALVOS_INTERNET])
    for x in res["internet"] or []:
        if isinstance(x, dict) and x.get("enviados"):
            log(f"{x['alvo']}: {x['perdidos']} perdidos, média {x['media_ms']} ms")
    servidores = []
    for sv in (a.get("dns") or []) + list(cfg.get("dns_extra") or []):
        if sv not in servidores and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", sv):
            servidores.append(sv)
    res["dns"] = fase("dns", len(servidores) * len(DOMINIOS_DNS), teste_dns, servidores)
    for x in res["dns"] if isinstance(res["dns"], list) else []:
        log(f"DNS {x['servidor']}: mediana {x['mediana_ms']} ms, {x['falhas']} falha(s)")
    res["mtu"] = fase("mtu", 12, teste_mtu)
    if (res["mtu"] or {}).get("caminho"):
        log(f"MTU do caminho: {res['mtu']['caminho']} (aviso de fragmentação {'ok' if res['mtu']['pmtud_ok'] else 'ausente'})")
    res["rota"] = fase("rota", 15, teste_rota)
    if (res["rota"] or {}).get("hops") is not None:
        log(f"Rota até 8.8.8.8: {res['rota'].get('saltos') or 'não chegou em 15'} saltos")
    if cfg.get("teste_velocidade"):
        res["velocidade"] = fase("velocidade", VEL_DOWN_RODADAS + VEL_UP_RODADAS, teste_velocidade)
    else:
        res["velocidade"] = {"pulado": True, "download_mbps": [], "upload_mbps": []}
    res["cancelado"] = CANCEL.is_set()
    res["fim"] = datetime.now().isoformat(timespec="seconds")
    if res["cancelado"]:  # não troca um relatório completo por um pela metade
        STATE.update(fase="cancelado", rodando=False)
        log("Diagnóstico interrompido; o relatório anterior foi mantido")
        return res
    # achados com a varredura atual (também recalculados toda vez que o relatório é montado)
    try:
        scan = _ultima_varredura()
        if scan:
            p = I.build_payload(scan)
            rel = avaliar(res, p, cfg)
            res.update(achados=rel["achados"], plano=rel["plano"], pendencias=rel["pendencias"])
    except Exception as e:
        log(f"Achados: falhou ({e})")
    save_diag(res)
    STATE.update(fase="concluida" if not res["cancelado"] else "cancelado", rodando=False)
    log("Diagnóstico " + ("interrompido" if res["cancelado"] else "concluído"))
    return res


def _ultima_varredura():
    try:
        with open(os.path.join(I.DADOS, "varredura.json"), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def estado():
    st = STATE
    return {"rodando": bool(st.get("rodando")), "fase": st.get("fase", "ocioso"), "feito": st.get("feito", 0),
            "total": st.get("total", 0), "etapas": st.get("etapas", []), "erro": st.get("erro"),
            "inicio": st.get("inicio"), "fase_inicio": st.get("fase_inicio"), "agora": time.time(),
            "log": st.get("log", [])[-40:]}


# ------------------------------------------------------------------ motor de achados
SEV_ORDEM = {"crit": 0, "warn": 1, "info": 2, "ok": 3}
PORTAS_BD = {3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 27017: "MongoDB",
             6379: "Redis", 5672: "RabbitMQ", 1883: "MQTT"}
EXPOSICAO = [("Telnet (23)", {23}), ("RDP (3389)", {3389}), ("Bancos de dados", {3306, 5432, 1433, 27017}),
             ("Filas e cache", {6379, 5672, 1883}), ("VPN PPTP (1723)", {1723})]


def _ip_curto(ip):
    return "." + ip.split(".")[-1] if ip else ""


def _nome(d):
    return d.get("nome") or d.get("modelo") or d.get("fabricante") or ("equipamento " + _ip_curto(d.get("ip")))


def _lista(itens):
    itens = [str(x) for x in itens if x]
    if len(itens) <= 1:
        return "".join(itens)
    return ", ".join(itens[:-1]) + " e " + itens[-1]


def _fmt(v, casas=1):
    if v is None:
        return "?"
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    s = f"{v:.{casas}f}" if isinstance(v, float) else str(v)
    return s.replace(".", ",")


def avaliar(diag, p, cfg):
    """Achados, plano de ação, pendências, resumo, infraestrutura e exposição de serviços."""
    devs = [d for d in p["dispositivos"] if d.get("online")]
    gw = (diag or {}).get("gw") or p["meta"].get("gw")
    rede = (diag or {}).get("rede") or p["meta"].get("rede")
    portas = {d["chave"]: {s["port"] for s in d.get("svcs", [])} for d in devs}
    aps = [d for d in devs if d.get("firmware") and (d.get("modelo") or "").upper().startswith("AP")]
    ap_ips = {d["ip"] for d in aps} | {d["ip"] for d in devs if d.get("firmware")}
    a = (diag or {}).get("adaptador") or {}
    wifi = a.get("tipo") == "wifi"
    achados = []

    def achado(id_, sev, titulo, texto, acao="", ips=()):
        achados.append({"id": id_, "sev": sev, "titulo": titulo, "texto": texto, "acao": acao,
                        "ips": sorted(set(ips), key=lambda x: tuple(int(n) for n in x.split(".")))})

    # R-01 rede interna
    g = (diag or {}).get("gateway") or {}
    if g.get("enviados"):
        lim = 60 if wifi else 20
        if (g.get("perda_pct") or 0) > 1 or (g.get("p95_ms") or 0) > lim:
            tit = "Perda de pacotes dentro da rede" if (g.get("perda_pct") or 0) > 1 else "Resposta lenta dentro da rede"
            achado("R-01", "crit", tit,
                   f"Dos {g['enviados']} pings enviados ao roteador ({gw}), {g['perdidos']} se perderam "
                   f"({_fmt(g['perda_pct'])}%) e 95% voltaram em até {_fmt(g.get('p95_ms'))} ms. Dentro da própria rede o "
                   + ("normal é perda zero e poucos milissegundos no Wi-Fi. " if wifi else
                      "normal no cabo é perda zero e menos de 1 ms. ")
                   + "Perda aqui deixa o sistema, as câmeras e a internet lentos ou travando, em todos os computadores "
                   "ao mesmo tempo.",
                   "Verificar o cabo deste computador, o switch e a porta do roteador; repetir o teste com outro cabo."
                   if not wifi else "Repetir o teste perto do AP e verificar o sinal e o canal do Wi-Fi.", [gw])

    # R-02 / R-03 link de internet
    v = (diag or {}).get("velocidade") or {}
    down, up = v.get("download_mbps") or [], v.get("upload_mbps") or []
    plano = cfg.get("plano_down_mbps")
    if down and plano:
        med = statistics.median(down)
        pct = med / plano
        if pct < 0.8:
            achado("R-02", "crit" if pct < 0.6 else "warn", f"Link de {_fmt(plano, 0)} Mbps pequeno para a rede",
                   f"No momento do teste sobravam {_fmt(round(med, 1))} Mbps de download ({round(pct * 100)}% dos "
                   f"{_fmt(plano, 0)} Mbps contratados; as rodadas ficaram entre {_fmt(min(down))} e {_fmt(max(down))} Mbps). "
                   f"O teste mede só a parte do link que estava livre: o resto estava em uso pelos {len(devs)} equipamentos "
                   "da rede, ou o provedor não está entregando o plano.",
                   "Ver no roteador quem mais consome, limitar câmeras e visitantes e avaliar aumentar o plano.")
    if len(up) >= 2 and max(up) > 0 and (max(up) - min(up)) > 0.5 * max(up):
        achado("R-03", "warn", "Upload oscilando",
               f"O upload variou de {_fmt(min(up))} a {_fmt(max(up))} Mbps entre as rodadas do teste. Oscilação grande "
               "costuma indicar algum equipamento enviando muitos dados ao mesmo tempo, como câmeras com acesso remoto, "
               "backup ou sincronização com a nuvem.",
               "Procurar visualização remota de câmeras, backup ou sincronização em nuvem rodando durante o expediente.")

    # R-04 tudo na mesma rede
    cams = [d for d in devs if d["cat"] == "camera"]
    comps = [d for d in devs if d["cat"] in ("computador", "servidor")]
    priv = [d for d in devs if d.get("mac_privado")]
    if cams and comps and priv:
        achado("R-04", "warn", "Todos os equipamentos na mesma rede",
               f"Câmeras e gravadores ({len(cams)}), computadores ({len(comps)}) e celulares ou visitantes com MAC "
               f"aleatório ({len(priv)}) estão todos na rede {rede}. Um celular infectado ou um visitante consegue "
               "enxergar as câmeras e o servidor, e o vídeo das câmeras disputa espaço com o caixa.",
               "Separar em VLANs: loja, CFTV e visitantes.")

    # R-05 firmware dos APs (WOM e rádios ficam fora)
    if aps:
        fws = {}
        for d in aps:
            fws.setdefault(d["firmware"], []).append(d)
        modelos = {}
        for d in aps:
            modelos[d["modelo"]] = modelos.get(d["modelo"], 0) + 1
        mtxt = _lista(f"{n} {m}" for m, n in sorted(modelos.items(), key=lambda x: -x[1]))
        if len(fws) > 1:
            det = "; ".join(f"{fw} em {_lista(_ip_curto(d['ip']) for d in ds)}" for fw, ds in fws.items())
            achado("R-05", "warn", "Firmwares diferentes entre os APs",
                   f"Os {len(aps)} access points Intelbras ({mtxt}) não estão na mesma versão: {det}. "
                   "Versões diferentes podem ter falhas de segurança já corrigidas e atrapalhar a troca do celular "
                   "de um AP para outro.",
                   "Atualizar todos para a mesma versão no site oficial da Intelbras.", [d["ip"] for d in aps])
        else:
            fw = next(iter(fws))
            achado("R-05", "ok", "APs com o mesmo firmware",
                   f"Os {len(aps)} access points Intelbras ({mtxt}) estão todos no firmware {fw}.",
                   "", [d["ip"] for d in aps])

    # R-06 Telnet
    tel = [d for d in devs if 23 in portas[d["chave"]]]
    if tel:
        achado("R-06", "info", f"Telnet ativo em {len(tel)} equipamento{'s' if len(tel) > 1 else ''}",
               f"{_lista(_nome(d) for d in tel)} aceita{'m' if len(tel) > 1 else ''} acesso por Telnet (porta 23). "
               "O Telnet é um acesso de administração antigo, sem criptografia: a senha passa aberta pela rede. "
               "Em impressoras e câmeras ele costuma vir ligado de fábrica, com a senha padrão.",
               "Desativar o Telnet e trocar as senhas padrão.", [d["ip"] for d in tel])

    # R-07 bancos de dados e filas
    bd = [(d, sorted(portas[d["chave"]] & set(PORTAS_BD))) for d in devs if d["ip"] != gw]
    bd = [(d, ps) for d, ps in bd if ps]
    if bd:
        so_bd = all(set(ps) <= {3306, 5432, 1433, 27017} for _, ps in bd)
        partes = [f"o {_nome(d)} ({_ip_curto(d['ip'])}) em {_lista(f'{PORTAS_BD[x]} ({x})' for x in ps)}" for d, ps in bd]
        redis = any(6379 in ps for _, ps in bd)
        achado("R-07", "warn", "Banco de dados aberto para toda a rede" if so_bd else
               "Banco de dados e filas abertos para toda a rede",
               f"Aceita{'m' if len(bd) > 1 else ''} conexões de qualquer equipamento da rede, inclusive dos celulares "
               f"no Wi-Fi: {_lista(partes)}." + (" O Redis costuma vir sem senha." if redis else ""),
               "Liberar essas portas no firewall do Windows só para os computadores que realmente usam esses "
               "serviços e conferir se todos exigem senha.", [d["ip"] for d, _ in bd])

    # R-08 PPTP no gateway
    gwd = next((d for d in devs if d["ip"] == gw), None)
    if gwd and 1723 in portas[gwd["chave"]]:
        achado("R-08", "info", "VPN PPTP ativa no roteador",
               f"O roteador ({gw}) aceita conexões de VPN pelo protocolo PPTP (porta 1723). O PPTP é antigo e a "
               "criptografia dele já foi quebrada: quem capturar a conexão consegue descobrir a senha.",
               "Trocar por L2TP/IPsec ou OpenVPN, ou desligar se ninguém usa.", [gw])

    # R-09 equipamento respondendo DNS
    dns_l = [d for d in devs if 53 in portas[d["chave"]] and d["ip"] != gw and d["ip"] not in ap_ips
             and (d.get("mac_privado") or d["cat"] == "computador")]
    if dns_l:
        def tipo(d):
            return "Um Mac" if d.get("so") == "macOS" else "Um computador" if d["cat"] == "computador" else \
                "Um equipamento com MAC aleatório"
        tit = f"{tipo(dns_l[0])} respondendo como servidor DNS" if len(dns_l) == 1 else \
            f"{len(dns_l)} equipamentos respondendo como servidor DNS"
        achado("R-09", "info", tit,
               f"{_lista(_nome(d) + ' (' + _ip_curto(d['ip']) + ')' for d in dns_l)} responde"
               f"{'m' if len(dns_l) > 1 else ''} na porta 53, a mesma que o roteador usa para traduzir os endereços da "
               "internet. Em Mac isso costuma ser o Compartilhamento de Internet ligado; em outro aparelho pode ser um "
               "repetidor que alguém ligou na rede. Se algum celular passar a usar esse equipamento como DNS, a internet "
               "dele depende desse aparelho ligado.",
               "Verificar o compartilhamento de internet (macOS) ou um repetidor não autorizado.", [d["ip"] for d in dns_l])

    # R-10 RDP
    rdp = [d for d in devs if 3389 in portas[d["chave"]]]
    if rdp:
        achado("R-10", "info", f"Acesso remoto (RDP) aberto em {len(rdp)} computador{'es' if len(rdp) > 1 else ''}",
               f"{_lista(_nome(d) for d in rdp)} aceita{'m' if len(rdp) > 1 else ''} conexão de Área de Trabalho Remota "
               "(porta 3389). Dentro da loja isso é normal para suporte, mas se o roteador redirecionar a 3389 para a "
               "internet, esses computadores ficam expostos a tentativas de senha o dia inteiro.",
               "Conferir no roteador que não existe redirecionamento da porta 3389 para a internet.", [d["ip"] for d in rdp])

    # R-11 DNS
    dns = [x for x in ((diag or {}).get("dns") or []) if isinstance(x, dict) and x.get("consultas")]
    usados = set(a.get("dns") or [])
    ruins = [x for x in dns if x.get("falhas") or (x.get("mediana_ms") or 0) > 150]
    if ruins:
        def desc(x):
            papel = "usado por este computador" if x["servidor"] in usados else "alternativo"
            if x.get("falhas") and x["falhas"] >= x["consultas"]:
                return f"{x['servidor']} ({papel}) não respondeu"
            return (f"{x['servidor']} ({papel}) respondeu em {_fmt(x.get('mediana_ms'))} ms"
                    + (f" e falhou {x['falhas']} de {x['consultas']} vezes" if x.get("falhas") else ""))
        achado("R-11", "warn", "DNS lento ou falhando",
               f"O DNS traduz o nome dos sites para endereços; quando ele demora, tudo parece lento para abrir. "
               f"{_lista(desc(x) for x in ruins)}. O normal é menos de 50 ms.",
               "Trocar o DNS no DHCP do roteador (por exemplo para 1.1.1.1 e 8.8.8.8).")

    # R-12 placa de rede
    vel = a.get("velocidade_mbps")
    if a.get("tipo") == "cabo" and vel and vel < 1000:
        achado("R-12", "warn", f"Este computador conectado a {vel} Mbps",
               f"A placa de rede deste computador negociou {vel} Mbps com o switch. No cabo, o normal hoje é 1000 Mbps; "
               "100 Mbps costuma indicar cabo ruim, conector mal crimpado ou porta antiga no switch. Isso também limita "
               "os testes deste relatório.", "Verificar o cabo e a porta do switch.")

    # R-13 MTU
    m = (diag or {}).get("mtu") or {}
    if m.get("caminho") and m["caminho"] < 1500:
        if not m.get("pmtud_ok"):
            achado("R-13", "warn", "Pacotes grandes sendo descartados",
                   f"O maior pacote que chega até a internet tem {m['caminho']} bytes, e o caminho não avisa quando um "
                   "pacote maior é descartado. Alguns sites e sistemas podem travar ao carregar ou ao enviar arquivos.",
                   "Ajustar o MTU/MSS da WAN no roteador.")
        else:
            achado("MTU", "ok", f"MTU de {m['caminho']} bytes, com aviso funcionando",
                   f"O link de internet usa pacotes de até {m['caminho']} bytes (o comum no cabo é 1500), mas avisa "
                   "corretamente quando um pacote é grande demais, então nada trava. Isso é normal em PPPoE, fibra com "
                   "VLAN ou VPN.")

    # R-OK1 cabeamento e roteador
    ids = {x["id"] for x in achados}
    if g.get("enviados") and not ids & {"R-01", "R-11", "R-12", "R-13"}:
        d0 = next((x for x in dns if x["servidor"] in usados and x.get("mediana_ms")), None) or \
            next((x for x in dns if x.get("mediana_ms")), None)
        achado("R-OK1", "ok", "Cabeamento e roteador",
               f"{g['enviados']} pings ao roteador com {g['perdidos']} perdido{'s' if g['perdidos'] != 1 else ''} e tempo "
               f"médio de {_fmt(g.get('media_ms'), 2)} ms."
               + (f" A placa de rede está a {vel} Mbps." if vel else "")
               + (f" O DNS responde em {_fmt(d0['mediana_ms'])} ms." if d0 else ""))

    ordem = ["R-01", "R-02", "R-03", "R-04", "R-05", "R-06", "R-07", "R-08", "R-09", "R-10", "R-11", "R-12", "R-13",
             "R-OK1", "MTU"]
    achados.sort(key=lambda x: (SEV_ORDEM[x["sev"]], ordem.index(x["id"]) if x["id"] in ordem else 99))
    return {"achados": achados, "plano": plano_acao(achados), "pendencias": pendencias(diag, cfg, p),
            "resumo": resumo(achados, devs, g), "infra": infraestrutura(devs, gw),
            "exposicao": [{"rotulo": r, "portas": sorted(ps), "n": len(ips), "ips": ips} for r, ps in EXPOSICAO
                          for ips in [sorted({d["ip"] for d in devs if portas[d["chave"]] & ps},
                                             key=lambda x: tuple(int(n) for n in x.split(".")))]]}


PASSOS = {  # id -> (grupo, título do passo sozinho, o que fazer)
    "R-01": ("rede", "Revisar cabo, switch e porta do roteador",
             "Testar este computador em outra porta do switch e trocar cabos e conectores suspeitos até a perda sumir."),
    "R-12": ("rede", "Trocar o cabo ou a porta deste computador",
             "Trocar o cabo deste computador ou a porta do switch até a placa negociar 1000 Mbps."),
    "R-13": ("rede", "Ajustar o MTU/MSS da internet no roteador",
             "Ajustar o MTU ou o MSS da conexão de internet no roteador para o valor medido."),
    "R-02": ("link", "Liberar banda e avaliar aumentar o plano",
             "Ver no roteador quem mais consome, limitar câmeras e visitantes e, se o link continuar cheio, pedir ao "
             "provedor um plano maior."),
    "R-03": ("link", "Encontrar o que faz o upload oscilar",
             "Procurar câmeras com acesso remoto, backup ou sincronização em nuvem rodando no horário da loja."),
    "R-04": ("vlan", "Separar a rede em VLANs (loja, CFTV e visitantes)",
             "Começar pelas câmeras e gravadores numa VLAN só deles e por uma rede de visitantes isolada no Wi-Fi; "
             "depois deixar computadores e servidor na VLAN da loja."),
    "R-05": ("firmware", "Atualizar o firmware dos APs",
             "Baixar a mesma versão no site oficial da Intelbras e atualizar todos os APs fora do horário da loja."),
    "R-06": ("legado", "Desativar o Telnet e trocar senhas padrão",
             "Desligar o Telnet nos equipamentos listados e trocar as senhas que ainda são as de fábrica."),
    "R-08": ("legado", "Desativar o PPTP no roteador",
             "Desligar o PPTP no roteador ou trocar por L2TP/IPsec ou OpenVPN."),
    "R-07": ("exposicao", "Restringir bancos de dados e filas",
             "Liberar os bancos de dados e filas no firewall do Windows só para os computadores que usam esses "
             "serviços, com senha em todos."),
    "R-10": ("exposicao", "Conferir que o RDP não está aberto para a internet",
             "Conferir no roteador que a porta 3389 não está redirecionada para a internet."),
    "R-09": ("dns_local", "Desligar o DNS que não é do roteador",
             "Desligar o compartilhamento de internet no Mac ou retirar o repetidor que não é da loja."),
    "R-11": ("dns", "Trocar o DNS entregue pelo roteador",
             "Configurar no DHCP do roteador um DNS mais rápido, como 1.1.1.1 e 8.8.8.8."),
}


def plano_acao(achados):
    grupos = {}
    for x in achados:
        if x["sev"] == "ok" or x["id"] not in PASSOS or not x.get("acao"):
            continue
        g = PASSOS[x["id"]][0]
        grupos.setdefault(g, []).append(x)
    passos = []
    for g, xs in grupos.items():
        ids = [x["id"] for x in xs]
        if g == "legado" and len(xs) > 1:
            titulo = "Desativar Telnet e PPTP e trocar senhas padrão"
        elif g == "exposicao" and len(xs) > 1:
            titulo = "Restringir bancos de dados e conferir o RDP"
        elif g == "link" and "R-02" in ids:
            titulo = PASSOS["R-02"][1]
        else:
            titulo = PASSOS[xs[0]["id"]][1]
        ips = sorted({ip for x in xs for ip in x.get("ips", [])}, key=lambda x: tuple(int(n) for n in x.split(".")))
        passos.append({"titulo": titulo, "texto": " ".join(PASSOS[x["id"]][2] for x in xs), "ips": ips, "achados": ids})
    return passos[:6]


def pendencias(diag, cfg, p):
    out = []
    if not cfg.get("plano_down_mbps"):
        out.append("Qual é o plano de internet contratado? Informe em Configurar para comparar com a velocidade medida.")
    a = (diag or {}).get("adaptador") or {}
    if a.get("tipo") == "cabo":
        out.append("Este computador está no cabo, sem Wi-Fi: sinal e canais do Wi-Fi não foram medidos.")
    v = (diag or {}).get("velocidade") or {}
    if v.get("pulado"):
        out.append("Velocidade não medida (teste desligado em Configurar).")
    elif v.get("erro") and not v.get("download_mbps"):
        out.append(f"Velocidade não medida: o teste falhou ({v['erro']}).")
    if diag and not diag.get("gw"):
        out.append("O roteador desta rede não foi encontrado: perda e latência interna não foram medidas.")
    if diag and diag.get("cancelado"):
        out.append("O diagnóstico foi interrompido antes do fim: alguns testes estão incompletos.")
    try:
        fim = datetime.fromisoformat(p["meta"].get("fim") or p["meta"]["inicio"])
        h = (datetime.now() - fim).total_seconds() / 3600
        if h > 24:
            out.append(f"A lista de equipamentos é da varredura de {fim:%d/%m/%Y %H:%M} ({int(h // 24)} dia(s) atrás).")
    except Exception:
        pass
    at = [d for d in p["dispositivos"] if d.get("online") and d.get("aceita_tudo")]
    if at:
        pl = len(at) > 1
        out.append(f"{_lista(_nome(d) + ' (' + _ip_curto(d['ip']) + ')' for d in at)} aceita{'m' if pl else ''} "
                   f"conexão em qualquer porta e depois bloquei{'am' if pl else 'a'} por alguns segundos (proteção do "
                   f"equipamento). Para {'esses equipamentos' if pl else 'esse equipamento'}, só as portas que responderam "
                   f"a um protocolo foram consideradas; confira os serviços ativos na tela de configuração "
                   f"{'de cada um' if pl else 'dele'}.")
    if diag and diag.get("rede") and diag["rede"] != p["meta"].get("rede"):
        out.append(f"Os testes foram feitos na rede {diag['rede']}, mas a última varredura é da rede {p['meta'].get('rede')}.")
    out.append("Sinal e canais do Wi-Fi em cada AP: o programa não entra nos APs. Tire um print da tela de status de cada AP.")
    out.append("Consumo de banda por equipamento: exige acesso ao roteador. Tire um print da tela de tráfego do roteador.")
    for linha in str(cfg.get("pendencias_extra") or "").splitlines():
        if linha.strip():
            out.append(linha.strip())
    return out


def resumo(achados, devs, g):
    """Até 3 frases; o trecho entre ** vira destaque."""
    ids = {x["id"]: x for x in achados}
    frases = []
    if "R-OK1" in ids:
        frases.append(f"A rede interna está saudável: **{g['enviados']} pings ao roteador com "
                      f"{g['perdidos']} perdido{'s' if g['perdidos'] != 1 else ''}** e resposta média de "
                      f"{_fmt(g.get('media_ms'), 2)} ms.")
    elif "R-01" in ids:
        frases.append(f"**{ids['R-01']['titulo']}**: {ids['R-01']['texto'].split('. ')[0]}.")
    principal = next((x for x in achados if x["sev"] == "crit" and x["id"] != "R-01"), None) or \
        next((x for x in achados if x["sev"] == "warn"), None)
    if principal:
        frases.append(f"{'Problema principal' if principal['sev'] == 'crit' else 'Ponto de atenção principal'}: "
                      f"**{principal['titulo']}**. {principal['texto'].split('. ')[0].rstrip('.')}.")
    if "R-04" in ids:
        frases.append(f"Cerca de **{len(devs)} equipamentos** dividem a mesma rede, entre câmeras, computadores e celulares.")
    return frases


def infraestrutura(devs, gw):
    linhas = []

    def ipsort(ds):
        return sorted((d["ip"] for d in ds), key=lambda x: tuple(int(n) for n in x.split(".")))

    def fabs(ds):
        c = {}
        for d in ds:
            f = d.get("fabricante") or ("MAC privado" if d.get("mac_privado") else "desconhecido")
            c[f] = c.get(f, 0) + 1
        return _lista(f"{f} ({n})" if len(c) > 1 else f for f, n in sorted(c.items(), key=lambda x: -x[1]))
    r = [d for d in devs if d["ip"] == gw]
    if r:
        linhas.append({"funcao": "Roteador (gateway)", "cat": "roteador", "qtd": 1, "ips": ipsort(r), "fabricante": fabs(r),
                       "detalhe": r[0].get("modelo") or ""})
    aps = [d for d in devs if d.get("firmware") and (d.get("modelo") or "").upper().startswith("AP")]
    grupos = {}
    for d in aps:
        grupos.setdefault((d["modelo"], d["firmware"]), []).append(d)
    for (mod, fw), ds in sorted(grupos.items(), key=lambda x: -len(x[1])):
        linhas.append({"funcao": "Access point", "cat": "roteador", "qtd": len(ds), "ips": ipsort(ds), "fabricante": fabs(ds),
                       "detalhe": f"{mod} · firmware {fw}"})
    radios = [d for d in devs if d.get("firmware") and d not in aps]
    for d in radios:
        linhas.append({"funcao": "Rádio / ponte Wi-Fi", "cat": "roteador", "qtd": 1, "ips": [d["ip"]],
                       "fabricante": fabs([d]), "detalhe": f"{d.get('modelo')} · firmware {d['firmware']}"})
    outros = [d for d in devs if d["cat"] == "roteador" and d["ip"] != gw and not d.get("firmware")]
    if outros:
        linhas.append({"funcao": "Outros equipamentos de rede", "cat": "roteador", "qtd": len(outros), "ips": ipsort(outros),
                       "fabricante": fabs(outros), "detalhe": ""})
    for cat, nome in (("camera", "Câmeras e gravadores"), ("servidor", "Servidores"), ("impressora", "Impressoras"),
                      ("acesso", "Controle de acesso e alarmes"), ("voip", "Telefonia IP")):
        ds = [d for d in devs if d["cat"] == cat]
        if ds:
            linhas.append({"funcao": nome, "cat": cat, "qtd": len(ds), "ips": ipsort(ds), "fabricante": fabs(ds),
                           "detalhe": _lista(sorted({_nome(d) for d in ds}))[:160] if cat in ("servidor",) else ""})
    return linhas


def relatorio(p, scan):
    """Relatório para o payload: medições do último diagnóstico + achados recalculados com a
    varredura e a configuração atuais (mudar o plano em Configurar já muda o R-02)."""
    diag = load_diag()
    if not diag:
        return None
    cfg = load_config()
    r = {k: v for k, v in diag.items() if k != "historico"}
    r.update(avaliar(diag, p, cfg))
    r["historico"] = diag.get("historico", [])[-5:]
    return r


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        alvo = sys.argv[1]
    else:  # sem argumento: a /24 deste computador
        alvo = str(ipaddress.ip_network((I.local_info()[0] or "127.0.0.1") + "/24", strict=False))
    executar(alvo)
    print(json.dumps({k: v for k, v in load_diag().items() if k not in ("historico",)}, ensure_ascii=False, indent=1)[:4000])
