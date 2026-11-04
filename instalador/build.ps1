# Gera o instalador completo do Inventário de Rede.
#   powershell -ExecutionPolicy Bypass -File instalador\build.ps1
# Requisitos (só na máquina que gera o instalador): Python 3.12+, Inno Setup 6
#   python -m pip install pyinstaller pywebview pillow
$ErrorActionPreference = "Stop"
$aqui = Split-Path -Parent $MyInvocation.MyCommand.Path
$raiz = Split-Path -Parent $aqui
Set-Location $raiz

Write-Host "1/4  Gerando ícone e imagens do assistente..." -ForegroundColor Cyan
python "$aqui\gerar_assets.py"

Write-Host "2/4  Conferindo base de fabricantes (dados\oui.csv)..." -ForegroundColor Cyan
if (-not (Test-Path "$raiz\dados\oui.csv")) {
    New-Item -ItemType Directory -Force "$raiz\dados" | Out-Null
    Invoke-WebRequest "https://standards-oui.ieee.org/oui/oui.csv" -OutFile "$raiz\dados\oui.csv" -UseBasicParsing
}
if (-not (Test-Path "$aqui\redist\MicrosoftEdgeWebView2RuntimeInstallerX64.exe")) {
    New-Item -ItemType Directory -Force "$aqui\redist" | Out-Null
    # WebView2 completo x64 (offline, ~200 MB) — instala sem internet na máquina de destino
    Invoke-WebRequest "https://go.microsoft.com/fwlink/?linkid=2124701" -OutFile "$aqui\redist\MicrosoftEdgeWebView2RuntimeInstallerX64.exe" -UseBasicParsing
}

Write-Host "3/4  Empacotando o programa com Python embutido (PyInstaller)..." -ForegroundColor Cyan
python -m PyInstaller --noconfirm --clean --distpath "$aqui\dist" --workpath "$aqui\build" "$aqui\InventarioRede.spec"

Write-Host "4/4  Compilando o instalador gráfico (Inno Setup)..." -ForegroundColor Cyan
$iscc = @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 não encontrado. Instale em https://jrsoftware.org/isdl.php" }
& $iscc /Q "$aqui\InventarioRede.iss"
if ($LASTEXITCODE -ne 0) { throw "Falha ao compilar o instalador" }

$out = Get-ChildItem "$raiz\Instalador-InventarioRede-*.exe" | Sort-Object LastWriteTime | Select-Object -Last 1
Write-Host ("Pronto: {0}  ({1:N1} MB)" -f $out.FullName, ($out.Length / 1MB)) -ForegroundColor Green
