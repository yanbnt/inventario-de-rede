# Gera os dois instaladores do Inventário de Rede:
#   Instalador-InventarioRede-<versão>-online.exe   (~14 MB)  baixa o WebView2 da Microsoft se faltar
#   Instalador-InventarioRede-<versão>-offline.exe  (~220 MB) traz o WebView2 completo, instala sem internet
#
#   powershell -ExecutionPolicy Bypass -File instalador\build.ps1
# Requisitos (só na máquina que gera o instalador): Python 3.12+, Inno Setup 6
#   python -m pip install pyinstaller pywebview pillow
$ErrorActionPreference = "Stop"
$aqui = Split-Path -Parent $MyInvocation.MyCommand.Path
$raiz = Split-Path -Parent $aqui
Set-Location $raiz

function Baixar($url, $destino) {
    if (-not (Test-Path $destino)) {
        New-Item -ItemType Directory -Force (Split-Path $destino) | Out-Null
        Write-Host "     baixando $(Split-Path $destino -Leaf)..."
        Invoke-WebRequest $url -OutFile $destino -UseBasicParsing
    }
}

Write-Host "1/4  Gerando ícone e imagens do assistente..." -ForegroundColor Cyan
python "$aqui\gerar_assets.py"

Write-Host "2/4  Conferindo base de fabricantes e componentes da Microsoft..." -ForegroundColor Cyan
Baixar "https://standards-oui.ieee.org/oui/oui.csv" "$raiz\dados\oui.csv"
Baixar "https://go.microsoft.com/fwlink/p/?LinkId=2124703" "$aqui\redist\MicrosoftEdgeWebview2Setup.exe"              # bootstrapper (~2 MB)
Baixar "https://go.microsoft.com/fwlink/?linkid=2124701"   "$aqui\redist\MicrosoftEdgeWebView2RuntimeInstallerX64.exe" # completo x64 (~200 MB)

Write-Host "3/4  Empacotando o programa com Python embutido (PyInstaller)..." -ForegroundColor Cyan
python -m PyInstaller --noconfirm --clean --distpath "$aqui\dist" --workpath "$aqui\build" "$aqui\InventarioRede.spec"

Write-Host "4/4  Compilando os instaladores gráficos (Inno Setup)..." -ForegroundColor Cyan
$iscc = @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 não encontrado. Instale em https://jrsoftware.org/isdl.php" }
foreach ($edicao in @(@{ Nome = "online"; Args = @() }, @{ Nome = "offline"; Args = @("/DOFFLINE") })) {
    Write-Host "     versão $($edicao.Nome)..."
    # o antivírus às vezes trava o .exe enquanto o Inno grava o ícone: tenta de novo
    for ($i = 1; $i -le 4; $i++) {
        & $iscc /Q @($edicao.Args) "$aqui\InventarioRede.iss"
        if ($LASTEXITCODE -eq 0) { break }
        Start-Sleep 6
    }
    if ($LASTEXITCODE -ne 0) { throw "Falha ao compilar a versão $($edicao.Nome)" }
}

Get-ChildItem "$raiz\Instalador-InventarioRede-*.exe" | ForEach-Object {
    Write-Host ("Pronto: {0}  ({1:N1} MB)" -f $_.Name, ($_.Length / 1MB)) -ForegroundColor Green
}
