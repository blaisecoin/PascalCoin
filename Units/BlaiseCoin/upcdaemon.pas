{
  Copyright (c) 2016 by Albert Molina
  Copyright (c) 2017 by BlaiseCoin developers

  Distributed under the MIT software license, see the accompanying file LICENSE
  or visit http://www.opensource.org/licenses/mit-license.php.

  This unit is a part of BlaiseCoin, a P2P crypto-currency.
}

unit upcdaemon;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, daemonapp,
  SyncObjs, UOpenSSL, UCrypto, UNode, UFileStorage, UFolderHelper, UWalletKeys, UConst, ULog, UNetProtocol,
  IniFiles,
  UThread, URPC, UPoolMining, UAccounts;

Const
  CT_INI_SECTION_GLOBAL = 'GLOBAL';
  CT_INI_IDENT_SAVELOGS = 'SAVELOGS';
  CT_INI_IDENT_RPC_PORT = 'RPC_PORT';
  CT_INI_IDENT_RPC_WHITELIST = 'RPC_WHITELIST';
  CT_INI_IDENT_RPC_SAVELOGS = 'RPC_SAVELOGS';
  CT_INI_IDENT_RPC_SERVERMINER_PORT = 'RPC_SERVERMINER_PORT';
  CT_INI_IDENT_MINER_B58_PUBLICKEY = 'RPC_SERVERMINER_B58_PUBKEY';
  CT_INI_IDENT_MINER_NAME = 'RPC_SERVERMINER_NAME';
  CT_INI_IDENT_MINER_MAX_CONNECTIONS = 'RPC_SERVERMINER_MAX_CONNECTIONS';

Type
  { TPCDaemonThread }

  TPCDaemonThread = class(TPCThread)
  private
    FIniFile : TIniFile;
  protected
    procedure BCExecute; override;
  public
    constructor Create;
    destructor Destroy; override;
  end;

  { TPCDaemon }

  TPCDaemon = class(TCustomDaemon)
  private
    FThread : TPCDaemonThread;
    procedure ThreadStopped (Sender : TObject);
  public
    function Start : Boolean; override;
    function Stop : Boolean; override;
    function Pause : Boolean; override;
    function Continue : Boolean; override;
    function Execute : Boolean; override;
    function ShutDown : Boolean; override;
    function Install : Boolean; override;
    function UnInstall: boolean; override;
  end;

  { TPCDaemonMapper }

  TPCDaemonMapper = class(TCustomDaemonMapper)
  private
    FLog : TLog;
    procedure OnPascalCoinInThreadLog(logtype : TLogType; Time : TDateTime; AThreadID : Cardinal; Const sender, logtext : AnsiString);
  protected
    procedure DoOnCreate; override;
    procedure DoOnDestroy; override;
  public
  end;


implementation

var _FLog : TLog;

{ TPCDaemonThread }

procedure TPCDaemonThread.BCExecute;
var
  FNode : TNode;
  FWalletKeys : TWalletKeysExt;
  FRPC : TRPCServer;
  FMinerServer : TPoolMiningServer;

  procedure InitRPCServer;
  var port : Integer;
  Begin
    port := FIniFile.ReadInteger(CT_INI_SECTION_GLOBAL,CT_INI_IDENT_RPC_PORT,-1);
    if (port<=0) then begin
      FIniFile.WriteInteger(CT_INI_SECTION_GLOBAL,CT_INI_IDENT_RPC_PORT,CT_JSONRPC_Port);
      port:=CT_JSONRPC_Port;
      TLog.NewLog(ltInfo,ClassName,'Saving RPC server port to IniFile: '+IntToStr(port));
    end;
    FRPC := TRPCServer.Create;
    FRPC.WalletKeys := FWalletKeys;
    FRPC.Port:=port;
    FRPC.Active:=true;
    FRPC.ValidIPs:=FIniFile.ReadString(CT_INI_SECTION_GLOBAL,CT_INI_IDENT_RPC_WHITELIST,'127.0.0.1;');
    TLog.NewLog(ltInfo,ClassName,'RPC server is active on port '+IntToStr(port));
    if FIniFile.ReadBool(CT_INI_SECTION_GLOBAL,CT_INI_IDENT_RPC_SAVELOGS,true) then begin
      FIniFile.WriteBool(CT_INI_SECTION_GLOBAL,CT_INI_IDENT_RPC_SAVELOGS,true);
      FRPC.LogFileName:= TFolderHelper.GetPascalCoinDataFolder+PathDelim+'blaisecoin_rpc.log';
      TLog.NewLog(ltInfo,ClassName,'Activating RPC logs on file '+FRPC.LogFileName);
    end else begin
      FIniFile.WriteBool(CT_INI_SECTION_GLOBAL,CT_INI_IDENT_RPC_SAVELOGS,false);
      TLog.NewLog(ltInfo,ClassName,'RPC logs not enabled on IniFile value '+CT_INI_IDENT_RPC_SAVELOGS+'=0');
    end;
  end;

  procedure InitRPCMinerServer;
  var i, port, maxconnections : Integer;
    s : String;
    pubkey : TAccountKey;
    errors : AnsiString;
    ECPK : TECPrivateKey;
  Begin
    i := FIniFile.ReadInteger(CT_INI_SECTION_GLOBAL,CT_INI_IDENT_RPC_SERVERMINER_PORT,-1);
    if (i<0) then i:=CT_JSONRPCMinerServer_Port;
    if (i>0) then begin
      port := i;
      FIniFile.WriteInteger(CT_INI_SECTION_GLOBAL,CT_INI_IDENT_RPC_SERVERMINER_PORT,port);
      pubkey := CT_TECDSA_Public_Nul;
      s := Trim(FIniFile.ReadString(CT_INI_SECTION_GLOBAL,CT_INI_IDENT_MINER_B58_PUBLICKEY,''));
      if (s='') or (not TAccountComp.AccountKeyFromImport(s,pubkey,errors)) then begin
        if s<>'' then TLog.NewLog(lterror,Classname,'Invalid INI file public key: '+errors);
        i := 0;
        while (i<FWalletKeys.Count) and (pubkey.EC_OpenSSL_NID=CT_TECDSA_Public_Nul.EC_OpenSSL_NID) do begin
          if (FWalletKeys.Key[i].CryptedKey<>'') then pubkey := FWalletKeys[i].AccountKey
          else inc(i);
        end;
        if (pubkey.EC_OpenSSL_NID=CT_TECDSA_Public_Nul.EC_OpenSSL_NID) then begin
          // New key
          ECPK := TECPrivateKey.Create;
          try
            ECPK.GenerateRandomPrivateKey(CT_Default_EC_OpenSSL_NID);
            FWalletKeys.AddPrivateKey('RANDOM NEW BY DAEMON '+FormatDateTime('yyyy-mm-dd hh:nn:dd',now),ECPK);
            pubkey := ECPK.PublicKey;
            FIniFile.WriteString(CT_INI_SECTION_GLOBAL,CT_INI_IDENT_MINER_B58_PUBLICKEY,
              TAccountComp.AccountKeyToExport(pubkey));
            TLog.NewLog(ltInfo,ClassName, 'Generated new pubkey for miner: '+TAccountComp.AccountKeyToExport(pubkey));
          finally
            ECPK.Free;
          end;
        end;
      end else begin
        // pubkey is mine?
        if (FWalletKeys.IndexOfAccountKey(pubkey)<0) then begin
          TLog.NewLog(lterror,classname,'WARNING: Using a public key without private key in wallet! '+TAccountComp.AccountKeyToExport(pubkey));
        end;
      end;
      i := FWalletKeys.IndexOfAccountKey(pubkey);
      s := Trim(FIniFile.ReadString(CT_INI_SECTION_GLOBAL,CT_INI_IDENT_MINER_NAME,''));
      if (SameText(s,'TIME')) then begin
        s := FormatDateTime('yyyy-mm-dd hh:nn',Now);
        TLog.NewLog(ltInfo,ClassName,'Generated new miner name: '+s);
      end;
      maxconnections:=FIniFile.ReadInteger(CT_INI_SECTION_GLOBAL,CT_INI_IDENT_MINER_MAX_CONNECTIONS,1000);
      TLog.NewLog(ltinfo,ClassName,Format('Activating RPC Miner Server on port %d, name "%s", max conections %d and public key %s',
        [port,s,maxconnections,TAccountComp.AccountKeyToExport(pubkey)]));
      FMinerServer := TPoolMiningServer.Create;
      FMinerServer.UpdateAccountAndPayload(pubkey,s);
      FMinerServer.Port:=port;
      FMinerServer.Active:=True;
      FMinerServer.MaxConnections:=maxconnections;
    end else begin
      TLog.NewLog(ltinfo,ClassName,'RPC Miner Server NOT ACTIVE (Ini file is '+CT_INI_IDENT_RPC_SERVERMINER_PORT+'=0)');
    end;
  end;

begin
  FMInerServer := nil;
  TLog.NewLog(ltinfo,Classname,'START BlaiseCoin Server');
  try
    try
      FWalletKeys := TWalletKeysExt.Create(Nil);
      // Load Node
      // Check OpenSSL dll
      if not LoadSSLCrypt then begin
        WriteLn('Cannot load '+SSL_C_LIB);
        WriteLn('To use this software make sure this file is available on you system or reinstall the application');
        raise Exception.Create('Cannot load '+SSL_C_LIB+#10+'To use this software make sure this file is available on you system or reinstall the application');
      end;
      TCrypto.InitCrypto;
      FWalletKeys.WalletFileName := TFolderHelper.GetPascalCoinDataFolder+PathDelim+'WalletKeys.dat';
      // Creating Node:
      FNode := TNode.Node;
      // RPC Server
      InitRPCServer;
      try
        // Check Database
        FNode.Bank.StorageClass := TFileStorage;
        TFileStorage(FNode.Bank.Storage).DatabaseFolder := TFolderHelper.GetPascalCoinDataFolder+PathDelim+'Data';
        // Reading database
        FNode.Node.Bank.DiskRestoreFromOperations(CT_MaxBlock);
        FWalletKeys.SafeBox := FNode.Node.Bank.SafeBox;
        FNode.Node.AutoDiscoverNodes(CT_Discover_IPs);
        FNode.Node.NetServer.Active := true;

        // RPC Miner Server
        InitRPCMinerServer;
        try
          Repeat
            Sleep(100);
          Until Terminated;
        finally
          FreeAndNil(FMinerServer);
        end;
      finally
        FreeAndNil(FRPC);
      end;
      FNode.NetServer.Active := false;
      TNetData.NetData.Free;
      FreeAndNil(FNode);
    except
      on e:Exception do begin
        TLog.NewLog(lterror,Classname,'Exception '+E.Classname+': '+E.Message);
      end;
    end;
  finally
    TLog.NewLog(ltinfo,Classname,'EXIT BlaiseCoin Server');
  end;
end;

constructor TPCDaemonThread.Create;
begin
  inherited Create(True);
  FIniFile := TIniFile.Create(ExtractFileDir(Application.ExeName)+PathDelim+'blaisecoin_daemon.ini');
  if FIniFile.ReadBool(CT_INI_SECTION_GLOBAL,CT_INI_IDENT_SAVELOGS,true) then begin
    _FLog.SaveTypes:=CT_TLogTypes_ALL;
    _FLog.FileName:=TFolderHelper.GetPascalCoinDataFolder+PathDelim+'blaisecoin_'+FormatDateTime('yyyymmddhhnn',Now)+'.log';
    FIniFile.WriteBool(CT_INI_SECTION_GLOBAL,CT_INI_IDENT_SAVELOGS,true);
  end else begin
    FIniFile.WriteBool(CT_INI_SECTION_GLOBAL,CT_INI_IDENT_SAVELOGS,false);
  end;
end;

destructor TPCDaemonThread.Destroy;
begin
  FreeAndNil(FIniFile);
  inherited Destroy;
end;


{ TPCDaemon }

procedure TPCDaemon.ThreadStopped(Sender: TObject);
begin
  FreeAndNil(FThread);
end;

function TPCDaemon.Start: Boolean;
begin
  Result:=inherited Start;
  TLog.NewLog(ltinfo,ClassName,'Daemon Start '+BoolToStr(Result));
  FThread:=TPCDaemonThread.Create;
  FThread.OnTerminate:=@ThreadStopped;
  FThread.FreeOnTerminate:=False;
  FThread.Resume;
end;

function TPCDaemon.Stop: Boolean;
begin
  Result:=inherited Stop;
  TLog.NewLog(ltinfo,ClassName,'Daemon Stop: '+BoolToStr(Result));
  FThread.Terminate;
end;

function TPCDaemon.Pause: Boolean;
begin
  Result:=inherited Pause;
  TLog.NewLog(ltinfo,ClassName,'Daemon pause: '+BoolToStr(Result));
  FThread.Suspend;
end;

function TPCDaemon.Continue: Boolean;
begin
  Result:=inherited Continue;
  TLog.NewLog(ltinfo,ClassName,'Daemon continue: '+BoolToStr(Result));
  FThread.Resume;
end;

function TPCDaemon.Execute: Boolean;
begin
  Result:=inherited Execute;
  TLog.NewLog(ltinfo,ClassName,'Daemon execute: '+BoolToStr(Result));
end;

function TPCDaemon.ShutDown: Boolean;
begin
  Result:=inherited ShutDown;
  TLog.NewLog(ltinfo,ClassName,'Daemon Shutdown: '+BoolToStr(Result));
  FThread.Terminate;
end;

function TPCDaemon.Install: Boolean;
begin
  Result:=inherited Install;
  TLog.NewLog(ltinfo,ClassName,'Daemon Install: '+BoolToStr(Result));
end;

function TPCDaemon.UnInstall: boolean;
begin
  Result:=inherited UnInstall;
  TLog.NewLog(ltinfo,ClassName,'Daemon UnInstall: '+BoolToStr(Result));
end;

{ TPCDaemonMapper }

procedure TPCDaemonMapper.OnPascalCoinInThreadLog(logtype: TLogType;
  Time: TDateTime; AThreadID: Cardinal; const sender, logtext: AnsiString);
var s : AnsiString;
begin
//  if not SameText(sender,TPCDaemonThread.ClassName) then exit;
  if logtype in [lterror,ltinfo] then begin
    if AThreadID=MainThreadID then s := ' MAIN:' else s:=' TID:';
    WriteLn(formatDateTime('dd/mm/yyyy hh:nn:ss.zzz',Time)+s+IntToHex(AThreadID,8)+' ['+CT_LogType[Logtype]+'] <'+sender+'> '+logtext);
  end;
end;

procedure TPCDaemonMapper.DoOnCreate;
var D : TDaemonDef;
begin
  inherited DoOnCreate;
  WriteLn('');
  WriteLn(formatDateTime('dd/mm/yyyy hh:nn:ss.zzz',now)+' Starting BlaiseCoin server');
  FLog := TLog.Create(Nil);
  FLog.OnInThreadNewLog:=@OnPascalCoinInThreadLog;
  _FLog := FLog;
  D:=DaemonDefs.Add as TDaemonDef;
  D.DisplayName:='BlaiseCoin Daemon';
  D.Name:='BlaiseCoinDaemon';
  D.DaemonClassName:='TPCDaemon';
  D.WinBindings.ServiceType:=stWin32;
end;

procedure TPCDaemonMapper.DoOnDestroy;
begin
  if Assigned(FLog) then begin
    FLog.OnInThreadNewLog:= nil;
    FreeAndNil(FLog);
  end;
  inherited DoOnDestroy;
end;

end.

