"""
Gera as capturas de tela do README com uma rede FICTÍCIA (nenhum dado real).

    python docs\\gerar_telas.py

Monta uma varredura e um diagnóstico de demonstração, gera o relatório estático e fotografa
cada página com o Microsoft Edge em modo headless (docs\\telas\\*.png).
"""
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TELAS = os.path.join(RAIZ, "docs", "telas")
TMP = tempfile.mkdtemp(prefix="scanner-demo-")
os.environ["SCANNER_DADOS"] = TMP
shutil.copyfile(os.path.join(RAIZ, "dados", "oui.csv"), os.path.join(TMP, "oui.csv"))
sys.path.insert(0, RAIZ)
import identificar as I  # noqa: E402
import diagnostico as Dg  # noqa: E402

REDE, GW, EU = "192.168.10.0/24", "192.168.10.1", "192.168.10.50"
I.local_info = lambda rede=None: (EU, GW)  # a rede de demonstração não é a deste computador
rnd = random.Random(7)


def mac(oui):
    return oui + ":" + ":".join(f"{rnd.randrange(256):02X}" for _ in range(3))


def privado():
    b = [rnd.randrange(256) for _ in range(6)]
    b[0] = (b[0] & 0xFC) | 0x02
    return ":".join(f"{x:02X}" for x in b)


def http(port, title=None, server=None, tls=False):
    s = {"port": port, "status": "HTTP/1.1 200 OK", "proto": "https" if tls else "http"}
    if tls:
        s["tls"] = True
    if title:
        s["title"] = title
    if server:
        s["server"] = server
    return s


INTEL, DELL, HP, LENOVO, POSITIVO, EPSON, ZEBRA, SAMSUNG, TPLINK, GRAND, SYNO, CTRLID = (
    "30:E1:F1", "F8:BC:12", "3C:52:82", "54:E1:AD", "00:1D:BA", "64:EB:8C", "00:07:4D", "8C:79:F5",
    "50:C7:BF", "00:0B:82", "00:11:32", "00:1F:68")
hosts = [
    {"ip": GW, "mac": mac("80:85:44"), "servicos": [http(80, "HTTPD_ac"), http(443, "HTTPD_ac", tls=True), {"port": 1723}]},
    {"ip": "192.168.10.21", "mac": mac(INTEL), "servicos": [{"port": 53}, http(80, "Intelbras"), http(443, "Intelbras", tls=True)],
     "descoberta": {"protocolo": "intelbras", "modelo": "AP 1350 AC-S", "firmware": "4.4.132"}},
    {"ip": "192.168.10.22", "mac": mac(INTEL), "servicos": [{"port": 53}, http(80, "Intelbras"), http(443, "Intelbras", tls=True)],
     "descoberta": {"protocolo": "intelbras", "modelo": "AP 1350 AC-S", "firmware": "4.4.132"}},
    {"ip": "192.168.10.23", "mac": mac("54:BA:D9"), "servicos": [{"port": 53}, http(80, "Intelbras")],
     "descoberta": {"protocolo": "intelbras", "modelo": "AP 1250 AC Max", "firmware": "4.4.132"}},
    {"ip": "192.168.10.24", "mac": mac(TPLINK), "servicos": [http(80, "TP-Link Switch")]},
] + [
    {"ip": f"192.168.10.{30 + i}", "mac": mac(INTEL), "servicos": [http(80, "WEB SERVICE"), {"port": 554, "proto": "rtsp"}, {"port": 37777}]}
    for i in range(4)
] + [
    {"ip": "192.168.10.35", "mac": mac(INTEL), "servicos": [http(80, "NVR"), {"port": 554, "proto": "rtsp"}, {"port": 37777}, {"port": 8000}]},
    {"ip": "192.168.10.40", "mac": mac(CTRLID), "servicos": [http(80, "Control iD - iDAccess")]},
    {"ip": EU, "mac": mac(DELL), "netbios": "PC-FINANCEIRO", "servicos": [{"port": 135}, {"port": 139}, {"port": 445}]},
    {"ip": "192.168.10.51", "mac": mac(DELL), "netbios": "PC-CAIXA-01", "servicos": [{"port": 135}, {"port": 139}, {"port": 445}, {"port": 3389}]},
    {"ip": "192.168.10.52", "mac": mac(POSITIVO), "netbios": "PC-CAIXA-02", "servicos": [{"port": 135}, {"port": 139}, {"port": 445}]},
    {"ip": "192.168.10.53", "mac": mac(LENOVO), "netbios": "NOTE-GERENCIA", "servicos": [{"port": 135}, {"port": 445}, {"port": 3389}]},
    {"ip": "192.168.10.54", "mac": mac(HP), "netbios": "PC-ESTOQUE", "servicos": [{"port": 135}, {"port": 139}, {"port": 445}]},
    {"ip": "192.168.10.60", "mac": mac(DELL), "netbios": "SRV-ARQUIVOS",
     "servicos": [{"port": 135}, {"port": 139}, {"port": 445}, {"port": 3389}, {"port": 1433},
                  http(80, "IIS Windows Server", "Microsoft-IIS/10.0"), http(443, "Sistema de Gestão", tls=True)]},
    {"ip": "192.168.10.61", "mac": mac(SYNO), "servicos": [http(5000, "Synology DiskStation"), http(5001, "Synology DiskStation", tls=True), {"port": 445}]},
    {"ip": "192.168.10.70", "mac": mac(EPSON), "servicos": [http(80, "EPSON L6270 Series"), http(443, "EPSON L6270 Series", tls=True),
                                                         {"port": 515, "proto": "lpd"}, {"port": 631}, {"port": 9100, "proto": "raw-print"}]},
    {"ip": "192.168.10.71", "mac": mac(HP), "servicos": [http(80, "HP LaserJet Pro M404"), {"port": 9100, "proto": "raw-print"}]},
    {"ip": "192.168.10.72", "mac": mac(ZEBRA), "servicos": [http(80, "Zebra ZD220"), {"port": 9100, "proto": "raw-print"}]},
    {"ip": "192.168.10.80", "mac": mac(SAMSUNG), "servicos": [{"port": 8001}, {"port": 8002}, {"port": 9197}]},
    {"ip": "192.168.10.90", "mac": mac(GRAND), "servicos": [http(80, "Grandstream GXP1610"), {"port": 5060}]},
    {"ip": "192.168.10.101", "mac": privado(), "servicos": []},
    {"ip": "192.168.10.102", "mac": privado(), "servicos": []},
    {"ip": "192.168.10.103", "mac": privado(), "servicos": [{"port": 62078}]},
]
for h in hosts:
    h.setdefault("netbios", None)
    h.setdefault("hostname", h["netbios"])
    h["ping"] = True
scan = {"rede": REDE, "inicio": "2026-11-16T09:12:00", "fim": "2026-11-16T09:14:05",
        "portas_varridas": "1-65535", "hosts": hosts}
with open(os.path.join(TMP, "varredura.json"), "w", encoding="utf-8") as f:
    json.dump(scan, f, ensure_ascii=False)
I.register_scan(scan)

amostras = [rnd.choice([0] * 12 + [1, 1, 2]) for _ in range(250)]
amostras[171] = 3
diag = {
    "inicio": "2026-11-16T09:20:00", "fim": "2026-11-16T09:22:40", "rede": REDE, "eu": EU, "gw": GW, "cancelado": False,
    "adaptador": {"nome": "Ethernet", "descricao": "Placa Gigabit", "tipo": "cabo", "velocidade_mbps": 1000,
                  "erros_rx": 0, "erros_tx": 0, "descartes": 0, "dns": [GW], "wifi": None},
    "gateway": Dg.resumo_ping(GW, amostras),
    "internet": [Dg.resumo_ping("8.8.8.8", [rnd.choice([8, 9, 9, 10, 11]) for _ in range(50)]),
                 Dg.resumo_ping("1.1.1.1", [rnd.choice([10, 11, 11, 12, 14]) for _ in range(50)])],
    "dns": [{"servidor": GW, "consultas": 4, "falhas": 0, "mediana_ms": 11.8, "max_ms": 96, "tempos": [96, 12.1, 11.5, 11.2]},
            {"servidor": "8.8.8.8", "consultas": 4, "falhas": 0, "mediana_ms": 9.4, "max_ms": 31, "tempos": [31, 9.6, 9.2, 9.1]}],
    "mtu": {"caminho": 1492, "pmtud_ok": True, "alvo": "8.8.8.8"},
    "rota": {"alvo": "8.8.8.8", "saltos": 9, "chegou": True, "hops": [{"n": 1, "ip": "100.64.0.1", "ms": 2, "fim": False}]},
    "velocidade": {"servidor": "speed.cloudflare.com", "download_mbps": [78.4, 85.1, 81.0], "upload_mbps": [34.2, 37.9],
                   "pulado": False, "erro": None},
}
with open(os.path.join(TMP, "diagnostico.json"), "w", encoding="utf-8") as f:
    json.dump(diag, f, ensure_ascii=False)
Dg.save_config({"local": "Loja Exemplo", "autor": "Equipe de TI", "plano_down_mbps": 100, "plano_up_mbps": 40, "teste_velocidade": True})

p = I.build_payload(scan)
p["meta"]["versao"] = __import__("app").VERSAO
html = os.path.join(TMP, "demo.html")
with open(html, "w", encoding="utf-8") as f:
    f.write(I.render_static(p))

EDGE = next((x for x in (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                         r"C:\Program Files\Microsoft\Edge\Application\msedge.exe") if os.path.exists(x)), None)
if not EDGE:
    sys.exit("Microsoft Edge não encontrado")
os.makedirs(TELAS, exist_ok=True)
url = "file:///" + html.replace("\\", "/")
for nome, pagina, alt in (("01-painel", "painel", 900), ("02-mapa-da-rede", "mapa", 900), ("03-dispositivos", "dispositivos", 760),
                          ("04-servicos", "servicos", 760), ("05-diagnostico", "diagnostico", 1500)):
    saida = os.path.join(TELAS, nome + ".png")
    subprocess.run([EDGE, "--headless=new", "--disable-gpu", "--no-first-run", "--hide-scrollbars",
                    f"--user-data-dir={os.path.join(TMP, 'edge')}", f"--window-size=1440,{alt}",
                    "--virtual-time-budget=4000", f"--screenshot={saida}", f"{url}#{pagina}"],
                   capture_output=True, timeout=90)
    print(nome, "ok" if os.path.exists(saida) else "FALHOU")
shutil.rmtree(TMP, ignore_errors=True)
