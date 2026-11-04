"""
Inventário de Rede — Make Distribuidora

Programa desktop: um servidor local (somente 127.0.0.1) + janela nativa (WebView2) com a interface.

    python app.py                 janela própria (padrão)
    python app.py --navegador     abre no navegador em vez da janela
    python app.py --porta 8770 --sem-navegador   só o servidor (desenvolvimento)
"""
import argparse
import ctypes
import sys
import tempfile
import asyncio
import ipaddress
import json
import os
import shutil
import subprocess
import threading
import urllib.request
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import identificar as I
import varredura as V

BASE = I.BASE
RESULT = os.path.join(I.DADOS, "varredura.json")
APP_HTML = os.path.join(BASE, "app.html")
OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
_lock = threading.Lock()
_scan_thread = None
_oui_job = {"rodando": False, "msg": ""}


# ------------------------------------------------------------------ dados
def last_result():
    st = V.STATE
    if st.get("resultado"):
        return st["resultado"]
    if os.path.exists(RESULT):
        with open(RESULT, encoding="utf-8") as f:
            return json.load(f)
    return None


def partial_result():
    st = V.STATE
    hosts = []
    for h in st.get("hosts", []):
        hosts.append({"ip": h, "mac": st.get("macs", {}).get(h), "hostname": None, "netbios": None,
                      "ping": h in st.get("pinged", []),
                      "servicos": [{"port": p, "pend": True} for p in sorted(st.get("abertas", {}).get(h, []))]})
    return {"rede": st.get("rede", ""), "inicio": st.get("inicio"), "fim": None,
            "portas_varridas": st.get("portas", ""), "hosts": hosts}


def payload():
    if V.STATE.get("rodando") and V.STATE.get("hosts"):
        return I.build_payload(partial_result(), parcial=True)
    d = last_result()
    if not d:
        return None
    inv = I.register_scan(d)
    return I.build_payload(d, inv)


def local_networks():
    nets = []
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command",
                              "Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike '127.*' "
                              "-and $_.IPAddress -notlike '169.254.*'} | Select-Object IPAddress,PrefixLength,InterfaceAlias "
                              "| ConvertTo-Json"], capture_output=True, timeout=20, creationflags=I.NOWIN).stdout.decode("utf-8", "replace")
        data = json.loads(out or "[]")
        for x in data if isinstance(data, list) else [data]:
            net = ipaddress.ip_network(f"{x['IPAddress']}/{x['PrefixLength']}", strict=False)
            if net.prefixlen < 16:
                net = ipaddress.ip_network(f"{x['IPAddress']}/24", strict=False)
            nets.append({"rede": str(net), "ip": x["IPAddress"], "interface": x["InterfaceAlias"]})
    except Exception:
        pass
    if not nets:
        ip, _ = I.local_info()
        if ip:
            nets.append({"rede": str(ipaddress.ip_network(f"{ip}/24", strict=False)), "ip": ip, "interface": ""})
    return nets


# ------------------------------------------------------------------ ações
def start_scan(rede, portas, conc, timeout):
    global _scan_thread
    net = ipaddress.ip_network(rede, strict=False)
    if net.prefixlen < 16:
        raise ValueError("Rede muito grande: use no máximo /16.")
    if not V.parse_ports(portas):
        raise ValueError("Faixa de portas inválida.")
    with _lock:
        if V.STATE.get("rodando"):
            raise RuntimeError("Já existe uma varredura em andamento.")
        V.reset_state(str(net), portas)
        args = argparse.Namespace(rede=str(net), portas=portas, saida=RESULT, conc=max(100, min(int(conc), 6000)),
                                  timeout=max(0.2, min(float(timeout), 3.0)), hosts="")

        def run():
            try:
                asyncio.run(V.main(args))
                if V.STATE.get("resultado"):
                    I.register_scan(V.STATE["resultado"])
            except Exception as e:
                V.STATE.update(erro=str(e), fase="erro")
                V.log(f"Erro: {e}")
            finally:
                V.STATE["rodando"] = False
        _scan_thread = threading.Thread(target=run, daemon=True)
        _scan_thread.start()


def update_oui():
    if _oui_job["rodando"]:
        return

    def run():
        _oui_job.update(rodando=True, msg="Baixando base de fabricantes do IEEE…")
        tmp = I.OUI_CSV + ".download"
        try:
            req = urllib.request.Request(OUI_URL, headers={"User-Agent": "Mozilla/5.0 (inventario-rede)"})
            with urllib.request.urlopen(req, timeout=120) as r, open(tmp, "wb") as f:
                shutil.copyfileobj(r, f)
            os.replace(tmp, I.OUI_CSV)
            n = I.load_oui()
            _oui_job["msg"] = f"Base atualizada: {n:,} fabricantes".replace(",", ".")
        except Exception as e:
            _oui_job["msg"] = f"Falha ao atualizar: {e}"
        finally:
            _oui_job["rodando"] = False
    threading.Thread(target=run, daemon=True).start()


# ------------------------------------------------------------------ HTTP
class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if not isinstance(body, (bytes, bytearray)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8") if "json" in ctype else str(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        try:
            if path in ("/", "/index.html"):
                with open(APP_HTML, "rb") as f:
                    return self.send(200, f.read(), "text/html; charset=utf-8")
            if path == "/api/dados":
                return self.send(200, payload())
            if path == "/api/estado":
                st = V.STATE
                return self.send(200, {
                    "rodando": bool(st.get("rodando")), "fase": st.get("fase", "ocioso"),
                    "feito": st.get("feito", 0), "total": st.get("total", 0), "rede": st.get("rede"),
                    "portas": st.get("portas"), "hosts": len(st.get("hosts", [])),
                    "abertas": sum(map(len, st.get("abertas", {}).values())),
                    "inicio": st.get("inicio"), "fase_inicio": st.get("fase_inicio"),
                    "agora": datetime.now().timestamp(), "erro": st.get("erro"),
                    "log": st.get("log", [])[-40:], "oui": dict(_oui_job, existe=os.path.exists(I.OUI_CSV)),
                    "modo": MODO, "versao": VERSAO, "dados": I.DADOS})
            if path == "/api/redes":
                return self.send(200, local_networks())
            if path == "/api/exportar":
                p = payload()
                if not p:
                    return self.send(404, {"erro": "Nenhuma varredura disponível."})
                html = I.render_static(p).encode("utf-8")
                name = "mapa-da-rede-" + datetime.now().strftime("%Y-%m-%d") + ".html"
                with open(os.path.join(I.DADOS, "ultimo-relatorio.html"), "wb") as f:
                    f.write(html)
                return self.send(200, html, "text/html; charset=utf-8",
                                 {"Content-Disposition": f'attachment; filename="{name}"'})
            return self.send(404, {"erro": "não encontrado"})
        except Exception as e:
            return self.send(500, {"erro": str(e)})

    def do_POST(self):
        # só aceita JSON (impede que outras páginas disparem ações via formulário)
        if "application/json" not in (self.headers.get("Content-Type") or ""):
            return self.send(415, {"erro": "Content-Type deve ser application/json"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
            path = self.path.split("?")[0]
            if path == "/api/varrer":
                start_scan(body.get("rede", ""), body.get("portas", "1-65535"),
                           body.get("conc", 2000), body.get("timeout", 0.5))
                return self.send(200, {"ok": True})
            if path == "/api/parar":
                V.CANCEL.set()
                V.log("Interrompendo… (os serviços já encontrados ainda serão identificados)")
                return self.send(200, {"ok": True})
            if path == "/api/dispositivo":
                e = I.update_device(body["chave"], body.get("nome"), body.get("categoria"), body.get("notas"))
                return self.send(200, {"ok": True, "dispositivo": e})
            if path == "/api/oui":
                update_oui()
                return self.send(200, {"ok": True})
            if path == "/api/encerrar":
                self.send(200, {"ok": True})
                V.CANCEL.set()
                SAIR.set()
                return
            return self.send(404, {"erro": "não encontrado"})
        except (ValueError, RuntimeError, KeyError) as e:
            return self.send(400, {"erro": str(e)})
        except Exception as e:
            return self.send(500, {"erro": str(e)})


# ------------------------------------------------------------------ janela desktop
VERSAO = "1.0.0"
TITULO = "Inventário de Rede — Make Distribuidora"
MODO = "servidor"
WINDOW = None
SAIR = threading.Event()  # sinalizado pelo botão "Encerrar" (modo navegador)


def open_target(target):
    """Abre URL/arquivo no programa padrão do Windows (navegador, VLC, PuTTY, mstsc...)."""
    try:
        if target.startswith(("http://", "https://")):
            webbrowser.open(target)
        else:
            os.startfile(target)
        return True
    except Exception as e:
        return str(e)


class Api:
    """Funções chamadas pela interface (window.pywebview.api.*)."""

    def abrir(self, url):
        return open_target(url)

    def rdp(self, addr):
        path = os.path.join(tempfile.gettempdir(), "inventario-" + addr.replace(":", "_") + ".rdp")
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"full address:s:{addr}\r\nprompt for credentials:i:1\r\nscreen mode id:i:2\r\n")
        return open_target(path)

    def exportar(self):
        import webview
        p = payload()
        if not p:
            return {"erro": "Nenhuma varredura disponível."}
        nome = "mapa-da-rede-" + datetime.now().strftime("%Y-%m-%d") + ".html"
        kind = getattr(getattr(webview, "FileDialog", None), "SAVE", None) or webview.SAVE_DIALOG
        res = WINDOW.create_file_dialog(kind, directory=os.path.join(os.path.expanduser("~"), "Documents"),
                                        save_filename=nome, file_types=("Página HTML (*.html)",))
        if not res:
            return {"cancelado": True}
        dest = res if isinstance(res, str) else res[0]
        if not dest.lower().endswith(".html"):
            dest += ".html"
        with open(dest, "w", encoding="utf-8") as f:
            f.write(I.render_static(p))
        return {"arquivo": dest}

    def abrir_arquivo(self, path):
        return open_target(path)

    def pasta_dados(self):
        return open_target(I.DADOS)


def single_instance():
    """Garante uma única janela aberta; se já existir, traz a existente para frente."""
    if os.name != "nt":
        return True
    k32, u32 = ctypes.windll.kernel32, ctypes.windll.user32
    single_instance.h = k32.CreateMutexW(None, False, "Local\\InventarioRedeMakeDistribuidora")
    if k32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        hwnd = u32.FindWindowW(None, TITULO)
        if hwnd:
            u32.ShowWindow(hwnd, 9)  # SW_RESTORE
            u32.SetForegroundWindow(hwnd)
        else:
            u32.MessageBoxW(None, "O Inventário de Rede já está aberto.", TITULO, 0x40)
        return False
    return True


def setup_logging():
    """No executável sem console, grava as mensagens em dados/app.log."""
    if I.FROZEN or sys.stdout is None:
        try:
            log = open(os.path.join(I.DADOS, "app.log"), "a", encoding="utf-8", buffering=1)
            sys.stdout = sys.stderr = log
        except Exception:
            pass
    print(f"--- {datetime.now():%d/%m/%Y %H:%M:%S} Inventário de Rede {VERSAO} — dados em {I.DADOS}")


def main():
    global MODO, WINDOW
    ap = argparse.ArgumentParser()
    ap.add_argument("--porta", type=int, default=0, help="0 = escolhe uma porta livre")
    ap.add_argument("--navegador", action="store_true", help="abrir no navegador em vez da janela")
    ap.add_argument("--sem-navegador", action="store_true", help="só o servidor (desenvolvimento)")
    a = ap.parse_args()
    setup_logging()
    if not a.sem_navegador and not single_instance():
        return
    I.load_oui()
    srv = ThreadingHTTPServer(("127.0.0.1", a.porta or (8770 if a.sem_navegador else 0)), H)  # só esta máquina
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    print(f"Servidor em {url}")

    if a.sem_navegador:
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
        return

    threading.Thread(target=srv.serve_forever, daemon=True).start()
    if not a.navegador:
        try:
            import webview
            MODO = "janela"
            for k, v in (("OPEN_EXTERNAL_LINKS_IN_BROWSER", True), ("ALLOW_DOWNLOADS", True)):
                try:
                    webview.settings[k] = v
                except Exception:
                    pass
            WINDOW = webview.create_window(TITULO, url, js_api=Api(), width=1380, height=880, min_size=(960, 620),
                                           background_color="#141D16", text_select=True)

            def ao_fechar():
                """Com varredura em andamento, pergunta antes de fechar (o progresso seria perdido)."""
                if not V.STATE.get("rodando"):
                    return True
                st = V.STATE
                pct = st.get("feito", 0) * 100 / max(st.get("total", 0), 1)
                r = ctypes.windll.user32.MessageBoxW(
                    None, f"Há uma varredura em andamento ({pct:.0f}% da fase atual).\n\n"
                          "Se fechar agora, a varredura será interrompida e o progresso perdido.\n\n"
                          "Fechar mesmo assim?", TITULO,
                    0x04 | 0x30 | 0x100 | 0x10000 | 0x40000)  # SIM/NÃO, alerta, padrão=Não, primeiro plano
                return r == 6  # IDYES; False cancela o fechamento
            WINDOW.events.closing += ao_fechar
            webview.start(gui="edgechromium", private_mode=False,
                          storage_path=os.path.join(I.DADOS, "webview"))
            print("Janela fechada — encerrando")
            V.CANCEL.set()
            srv.shutdown()
            return
        except Exception as e:
            import traceback
            traceback.print_exc()
            try:
                import webview.util as wu
                print("webview.util:", wu.__file__)
            except Exception:
                pass
            print(f"Janela própria indisponível ({e!r}); abrindo no navegador")
            MODO = "navegador"
            if os.name == "nt":
                ctypes.windll.user32.MessageBoxW(
                    None, "Não foi possível abrir a janela própria (componente Microsoft WebView2 ausente).\n\n"
                          "O Inventário de Rede vai abrir no seu navegador. Para encerrar, use o botão "
                          "“Encerrar” no menu lateral.", TITULO, 0x30)
    MODO = "navegador"
    webbrowser.open(url)
    try:
        while not SAIR.wait(1):
            pass
    except KeyboardInterrupt:
        pass
    print("Encerrado pelo usuário")
    srv.shutdown()
    srv.server_close()


if __name__ == "__main__":
    main()
