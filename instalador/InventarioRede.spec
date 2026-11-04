# PyInstaller — gera dist\InventarioRede\InventarioRede.exe com Python e todas as bibliotecas embutidas.
# Uso: pyinstaller --noconfirm instalador\InventarioRede.spec   (ou rode instalador\build.ps1)
import os

import webview

RAIZ = os.path.abspath(os.path.join(SPECPATH, ".."))
ASSETS = os.path.join(SPECPATH, "assets")

# DLLs do WebView2 e scripts JS que o pywebview carrega em tempo de execução
WV = os.path.dirname(webview.__file__)
WV_DATA = []
for pasta in ("lib", "js"):
    for raiz, _, arquivos in os.walk(os.path.join(WV, pasta)):
        for nome in arquivos:
            if nome.endswith(".jar") or "arm64" in raiz or "win-x86" in raiz:
                continue
            WV_DATA.append((os.path.join(raiz, nome), os.path.relpath(raiz, os.path.dirname(WV))))

a = Analysis(
    [os.path.join(RAIZ, "app.py")],
    pathex=[RAIZ],
    datas=[
        (os.path.join(RAIZ, "app.html"), "."),
        (os.path.join(RAIZ, "dados", "oui.csv"), "."),   # base de fabricantes (copiada para os dados do usuário)
        (os.path.join(ASSETS, "icone.ico"), "."),
    ] + WV_DATA,
    hiddenimports=["webview.platforms.edgechromium", "webview.platforms.winforms", "clr"],
    excludes=["tkinter", "unittest", "pydoc_data", "PIL", "numpy"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="InventarioRede",
    icon=os.path.join(ASSETS, "icone.ico"),
    version=os.path.join(SPECPATH, "versao.txt"),
    console=False,          # programa de janela: sem console
    upx=False,
)
coll = COLLECT(exe, a.binaries, a.datas, name="InventarioRede", upx=False)
