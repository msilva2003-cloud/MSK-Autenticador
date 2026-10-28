#define AppVersion "0.1.7"

[Setup]
AppId={{F49226CA-C6FD-4059-A70B-AB95EFD9EFEA}
AppName=MSK Autenticador
AppVersion={#AppVersion}
AppVerName=MSK Autenticador {#AppVersion}
AppPublisher=MSK
AppPublisherURL=https://github.com/msilva2003-cloud/MSK-Autenticador
AppSupportURL=https://github.com/msilva2003-cloud/MSK-Autenticador/issues
AppUpdatesURL=https://github.com/msilva2003-cloud/MSK-Autenticador/releases
DefaultDirName={localappdata}\Programs\MSK Autenticador
DefaultGroupName=MSK Autenticador
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
SetupArchitecture=x64
OutputDir=dist
OutputBaseFilename=MSK-Autenticador-Setup-{#AppVersion}-windows-x64
SetupIconFile=assets\app.ico
UninstallDisplayIcon={app}\MSKAuthenticator.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "Criar atalho na área de trabalho"; GroupDescription: "Atalhos:"; Flags: unchecked

[Files]
Source: "build\Release\MSKAuthenticator.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "LICENSE-ZXing.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "LICENSE-Zint.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\MSK Autenticador"; Filename: "{app}\MSKAuthenticator.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\MSK Autenticador"; Filename: "{app}\MSKAuthenticator.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\MSKAuthenticator.exe"; Description: "Abrir MSK Autenticador"; Flags: nowait postinstall skipifsilent

[Code]
function IsAutoUpdate: Boolean;
begin
  Result := ExpandConstant('{param:AUTOUPDATE|0}') = '1';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ErrorCode: Integer;
begin
  if (CurStep = ssPostInstall) and IsAutoUpdate then
    ShellExec('', ExpandConstant('{app}\MSKAuthenticator.exe'), '', ExpandConstant('{app}'),
      SW_SHOWNORMAL, ewNoWait, ErrorCode);
end;

// O cofre fica em %LOCALAPPDATA%\MSKAuthenticator, fora de {app}.
// A desinstalacao nao remove nem exporta os segredos do usuario.
