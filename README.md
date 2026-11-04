# Inventário de Rede — Make Distribuidora

Programa desktop que descobre, identifica (pelo MAC, portas e páginas web) e mapeia todos os dispositivos da rede.

## Instalar em outra máquina / empresa

Baixe **`Instalador-InventarioRede-1.0.0-offline.exe`** (≈210 MB) na página de [Releases](../../releases/latest) e execute — é um único arquivo com tudo dentro e **instala sem internet**.
Ele já inclui Python, bibliotecas, interface e a base de fabricantes. Requisitos: Windows 10/11 64 bits.
Inclui também o Microsoft WebView2 completo (offline): se a máquina não tiver, o instalador instala sem precisar de internet.

- Instala em `C:\Program Files\Inventario de Rede` (ou só para o usuário, se escolher no início).
- Dados (inventário, histórico, varreduras): `%LOCALAPPDATA%\InventarioRede\dados` — faça cópia dessa pasta para guardar.
- Instalação silenciosa (TI): `Instalador-InventarioRede-1.0.0-offline.exe /VERYSILENT /SUPPRESSMSGBOXES`

## Estrutura do projeto

| Arquivo | O que é |
|---|---|
| `app.py` | Programa principal: servidor local (127.0.0.1) + janela nativa (pywebview/WebView2) |
| `app.html` | Interface (Material Design, cores Make): painel, mapa, dispositivos, serviços, varredura |
| `varredura.py` | Scanner: descoberta (ping/ARP), portas TCP, identificação de serviços, nomes |
| `identificar.py` | Fabricante pelo MAC, categorias por evidências, inventário persistente, exportação |
| `dados\` | Dados locais de desenvolvimento (não versionados) e `oui.csv` (baixado pelo build) |
| `instalador\` | Build: `build.ps1`, `InventarioRede.spec` (PyInstaller), `InventarioRede.iss` (Inno Setup), imagens |

## Rodar sem instalar (desenvolvimento)

```
python app.py               # janela própria
python app.py --navegador   # no navegador
```

## Gerar o instalador de novo (após mudar o código)

Requisitos só na máquina que gera: Python 3.12+, `pip install pyinstaller pywebview pillow`, Inno Setup 6.
O `build.ps1` baixa sozinho a base de fabricantes (IEEE) e o instalador offline do WebView2 (Microsoft, ~200 MB).

```
powershell -ExecutionPolicy Bypass -File instalador\build.ps1
```

Para mudar a versão, altere `VERSAO` em `app.py`, `AppVersion` em `instalador\InventarioRede.iss` e `instalador\versao.txt`.

> O instalador novo sai na raiz desta pasta. Gere a partir de uma pasta com caminho curto (ex.: Área de Trabalho). Caminhos com mais de
> 260 caracteres impedem o executável de achar as DLLs do WebView2 quando roda direto de `instalador\dist`.
