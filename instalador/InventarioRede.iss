; Instalador gráfico do Inventário de Rede — Make Distribuidora
; Compilar: instalador\build.ps1  (gera as duas versões)
;   versão online  (~14 MB):  ISCC.exe instalador\InventarioRede.iss
;   versão offline (~220 MB): ISCC.exe /DOFFLINE instalador\InventarioRede.iss

#ifdef OFFLINE
  #define Edicao  "offline"
  #define WV2File "MicrosoftEdgeWebView2RuntimeInstallerX64.exe"
#else
  #define Edicao  "online"
  #define WV2File "MicrosoftEdgeWebview2Setup.exe"
#endif

#define AppName      "Inventário de Rede"
#define AppVersion   "1.0.0"
#define AppPublisher "Make Distribuidora"
#define AppURL       "https://makedistribuidora.com.br"
#define AppExe       "InventarioRede.exe"
; usado só dentro de [Code] (string Pascal): chave simples, sem o escape "{{" das outras seções
#define WebView2Guid "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"

[Setup]
AppId={{6E4C2B1A-7D3F-4F8E-9B52-1A0C9E7D4F21}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppCopyright=© 2026 {#AppPublisher}
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription=Instalador do {#AppName}
DefaultDirName={autopf}\Inventario de Rede
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
WizardStyle=modern
WizardSizePercent=110
WizardImageFile=assets\wizard-164.bmp,assets\wizard-328.bmp
WizardSmallImageFile=assets\wizard-small-55.bmp,assets\wizard-small-110.bmp
SetupIconFile=assets\icone.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
InfoBeforeFile=termos.txt
AppMutex=Local\InventarioRedeMakeDistribuidora
CloseApplications=yes
OutputDir=..
OutputBaseFilename=Instalador-InventarioRede-{#AppVersion}-{#Edicao}
Compression=lzma2/ultra64
SolidCompression=yes
ShowLanguageDialog=no

[Languages]
Name: "ptbr"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[CustomMessages]
ptbr.TaskDesktop=Criar atalho na Área de Trabalho
ptbr.LaunchApp=Abrir o {#AppName} agora
#ifdef OFFLINE
ptbr.InstallingWebView=Instalando o componente Microsoft WebView2 (janela do programa)…
ptbr.WebViewFail=Não foi possível instalar o Microsoft WebView2 (código %1).%n%nO {#AppName} funcionará normalmente, mas abrirá no navegador em vez da janela própria. Tente rodar este instalador de novo como administrador.
#else
ptbr.InstallingWebView=Baixando e instalando o componente Microsoft WebView2 (janela do programa)…
ptbr.WebViewFail=Não foi possível instalar o Microsoft WebView2 (código %1).%n%nEsta é a versão online do instalador, que baixa o componente da Microsoft: verifique a internet ou use a versão offline.%n%nO {#AppName} funcionará normalmente, mas abrirá no navegador em vez da janela própria.
#endif
ptbr.AskDeleteData=Deseja apagar também o inventário, o histórico e as varreduras salvas deste usuário?%n%n(%1)%n%nEscolha "Não" para manter os dados caso vá reinstalar.

[Tasks]
Name: "desktopicon"; Description: "{cm:TaskDesktop}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "dist\InventarioRede\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "termos.txt"; DestDir: "{app}"; DestName: "LEIA-ME.txt"; Flags: ignoreversion
; WebView2 — offline: instalador completo (~200 MB, sem internet); online: bootstrapper (~2 MB, baixa da Microsoft).
; Só é extraído e executado se a máquina não tiver o componente.
Source: "redist\{#WV2File}"; DestDir: "{tmp}"; Flags: deleteafterinstall nocompression; Check: NeedsWebView2

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; Comment: "Identifica e mapeia os dispositivos da rede"
Name: "{autoprograms}\{#AppName} (no navegador)"; Filename: "{app}\{#AppExe}"; Parameters: "--navegador"; Comment: "Abre o Inventário de Rede no navegador"
Name: "{autoprograms}\Desinstalar {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon; Comment: "Identifica e mapeia os dispositivos da rede"

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchApp}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
function WebView2Version(Root: Integer; Key: String): String;
begin
  Result := '';
  if not RegQueryStringValue(Root, Key, 'pv', Result) then
    Result := '';
end;

{ Procura msedgewebview2.exe em <Base>\<versão>\ — vale mesmo quando o registro não tem a chave
  (Windows 11, Edge gerenciado pela empresa, instalação feita por outro programa). }
function WebView2FilesIn(Base: String): Boolean;
var
  F: TFindRec;
begin
  Result := False;
  if FindFirst(AddBackslash(Base) + '*', F) then
  try
    repeat
      if (F.Attributes and FILE_ATTRIBUTE_DIRECTORY <> 0) and (F.Name <> '.') and (F.Name <> '..') and
         FileExists(AddBackslash(Base) + F.Name + '\msedgewebview2.exe') then
      begin
        Result := True;
        Exit;
      end;
    until not FindNext(F);
  finally
    FindClose(F);
  end;
end;

function WebView2Present: Boolean;
var
  V: String;
begin
  { 1) registro (instalação padrão do Evergreen Runtime) }
  V := WebView2Version(HKLM, 'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{#WebView2Guid}');
  if (V = '') or (V = '0.0.0.0') then
    V := WebView2Version(HKLM, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{#WebView2Guid}');
  if (V = '') or (V = '0.0.0.0') then
    V := WebView2Version(HKCU, 'Software\Microsoft\EdgeUpdate\Clients\{#WebView2Guid}');
  Result := (V <> '') and (V <> '0.0.0.0');
  { 2) arquivos no disco (por máquina e por usuário) }
  if not Result then
    Result := WebView2FilesIn(ExpandConstant('{commonpf32}\Microsoft\EdgeWebView\Application')) or
              WebView2FilesIn(ExpandConstant('{commonpf64}\Microsoft\EdgeWebView\Application')) or
              WebView2FilesIn(ExpandConstant('{localappdata}\Microsoft\EdgeWebView\Application'));
  if Result then
    Log('WebView2: já presente (registro: ' + V + ')')
  else
    Log('WebView2: ausente — será instalado');
end;

function NeedsWebView2: Boolean;
begin
  Result := not WebView2Present;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Code: Integer;
begin
  if (CurStep = ssPostInstall) and NeedsWebView2 then
  begin
    WizardForm.StatusLabel.Caption := CustomMessage('InstallingWebView');
    WizardForm.ProgressGauge.Style := npbstMarquee;
    try
      if not Exec(ExpandConstant('{tmp}\{#WV2File}'), '/silent /install', '',
                  SW_HIDE, ewWaitUntilTerminated, Code) or NeedsWebView2 then
      begin
        Log(Format('WebView2: falhou, código %d', [Code]));
        if not WizardSilent then
          MsgBox(FmtMessage(CustomMessage('WebViewFail'), [IntToStr(Code)]), mbInformation, MB_OK);
      end
      else
        Log(Format('WebView2: instalado (código %d)', [Code]));
    finally
      WizardForm.ProgressGauge.Style := npbstNormal;
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Pasta: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    Pasta := ExpandConstant('{localappdata}\InventarioRede');
    if DirExists(Pasta) and not UninstallSilent then
      if MsgBox(FmtMessage(CustomMessage('AskDeleteData'), [Pasta]), mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(Pasta, True, True, True);
  end;
end;
