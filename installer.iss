; Inno Setup Script - Baidu Cloud Downloader

[Setup]
AppName=Baidu Cloud Downloader
AppVersion=1.0
AppPublisher=Baidu Downloader
DefaultDirName={autopf}\BaiduDownloader
DefaultGroupName=Baidu Cloud Downloader
OutputBaseFilename=BaiduDownloader_Setup
Compression=lzma2
SolidCompression=yes
UninstallDisplayName=Baidu Cloud Downloader
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "korean"; MessagesFile: "compiler:Languages\Korean.isl"
Name: "japanese"; MessagesFile: "compiler:Languages\Japanese.isl"
Name: "arabic"; MessagesFile: "compiler:Languages\Arabic.isl"
Name: "armenian"; MessagesFile: "compiler:Languages\Armenian.isl"
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"
Name: "bulgarian"; MessagesFile: "compiler:Languages\Bulgarian.isl"
Name: "catalan"; MessagesFile: "compiler:Languages\Catalan.isl"
Name: "corsican"; MessagesFile: "compiler:Languages\Corsican.isl"
Name: "czech"; MessagesFile: "compiler:Languages\Czech.isl"
Name: "danish"; MessagesFile: "compiler:Languages\Danish.isl"
Name: "dutch"; MessagesFile: "compiler:Languages\Dutch.isl"
Name: "finnish"; MessagesFile: "compiler:Languages\Finnish.isl"
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "german"; MessagesFile: "compiler:Languages\German.isl"
Name: "hebrew"; MessagesFile: "compiler:Languages\Hebrew.isl"
Name: "hungarian"; MessagesFile: "compiler:Languages\Hungarian.isl"
Name: "italian"; MessagesFile: "compiler:Languages\Italian.isl"
Name: "norwegian"; MessagesFile: "compiler:Languages\Norwegian.isl"
Name: "polish"; MessagesFile: "compiler:Languages\Polish.isl"
Name: "portuguese"; MessagesFile: "compiler:Languages\Portuguese.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "slovak"; MessagesFile: "compiler:Languages\Slovak.isl"
Name: "slovenian"; MessagesFile: "compiler:Languages\Slovenian.isl"
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "swedish"; MessagesFile: "compiler:Languages\Swedish.isl"
Name: "tamil"; MessagesFile: "compiler:Languages\Tamil.isl"
Name: "thai"; MessagesFile: "compiler:Languages\Thai.isl"
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"
Name: "ukrainian"; MessagesFile: "compiler:Languages\Ukrainian.isl"

[Files]
Source: "dist\BaiduDownloader.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Baidu Cloud Downloader"; Filename: "{app}\BaiduDownloader.exe"
Name: "{group}\Uninstall Baidu Cloud Downloader"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Baidu Cloud Downloader"; Filename: "{app}\BaiduDownloader.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Run]
Filename: "{app}\BaiduDownloader.exe"; Description: "{cm:LaunchProgram,Baidu Cloud Downloader}"; Flags: nowait postinstall skipifsilent

[Code]
function GetAppLang: String;
var
  Lang: String;
begin
  Lang := ActiveLanguage;
  if Lang = 'korean' then Result := 'ko'
  else if Lang = 'japanese' then Result := 'ja'
  else if (Lang = 'chinese') or (Pos('chinese', Lang) > 0) then Result := 'zh'
  else Result := 'en';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ConfigPath: String;
  Lines: TArrayOfString;
begin
  if CurStep = ssPostInstall then
  begin
    ConfigPath := ExpandConstant('{app}\config.json');
    SetArrayLength(Lines, 3);
    Lines[0] := '{';
    Lines[1] := '  "language": "' + GetAppLang + '"';
    Lines[2] := '}';
    if not FileExists(ConfigPath) then
      SaveStringsToUTF8File(ConfigPath, Lines, False);
  end;
end;
