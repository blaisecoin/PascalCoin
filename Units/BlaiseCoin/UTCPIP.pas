{
  Copyright (c) 2016 by Albert Molina
  Copyright (c) 2017 by BlaiseCoin developers

  Distributed under the MIT software license, see the accompanying file LICENSE
  or visit http://www.opensource.org/licenses/mit-license.php.

  This unit is a part of BlaiseCoin, a P2P crypto-currency.
}

unit UTCPIP;

interface

{$IFDEF FPC}
  {$mode objfpc}
{$ENDIF}

{$I config.inc}

{$IFDEF DelphiSockets}{$IFDEF Synapse}DelphiSockets and Synapse are defined! Choose one!{$ENDIF}{$ENDIF}
{$IFNDEF DelphiSockets}{$IFNDEF Synapse}Nor DelphiSockets nor Synapse are defined! Choose one!{$ENDIF}{$ENDIF}

uses
  {$IFDEF UNIX}
  //cthreads,
  {$ENDIF}
  {$IFDEF Synapse}
  blcksock,
  synsock,  // synsock choose Socket by OS
  {$ENDIF}
  {$IFDEF DelphiSockets}
  Sockets,
  {$ENDIF}
  Classes, Sysutils,
  UThread, SyncObjs;

type
  {$IFDEF DelphiSockets}
  TTCPBlockSocket = TCustomIpClient;
  {$ENDIF}

  { TNetTcpIpClient }

  TNetTcpIpClient = class(TComponent)
  private
    FTcpBlockSocket : TTCPBlockSocket;
    {$IFDEF Synapse}
    FConnected : Boolean;
    FRemoteHost : AnsiString;
    FRemotePort : Word;
    FBytesReceived, FBytesSent : Int64;
    FLock : TPCCriticalSection;
    {$ENDIF}
    FOnConnect: TNotifyEvent;
    FOnDisconnect: TNotifyEvent;
    FSocketError: Integer;
    FLastCommunicationTime : TDateTime;
    function GetConnected: Boolean;
    function GetRemoteHost: AnsiString;
    function GetRemotePort: Word;
    procedure SetRemoteHost(const Value: AnsiString);
    procedure SetRemotePort(const Value: Word);
    procedure SetOnConnect(const Value: TNotifyEvent);
    procedure SetOnDisconnect(const Value: TNotifyEvent);
    procedure SetSocketError(const Value: Integer);
    {$IFDEF DelphiSockets}
    procedure TCustomIpClient_OnError(Sender: TObject; ASocketError: Integer);
    {$ENDIF}
  protected
    procedure DoOnConnect; Virtual;
    function ReceiveBuf(var Buf; BufSize: Integer): Integer;
    function SendStream(Stream : TStream) : Int64;
    procedure DoWaitForData(WaitMilliseconds : Integer; var HasData : Boolean); virtual;
  public
    constructor Create(AOwner : TComponent); override;
    destructor Destroy; override;
    function ClientRemoteAddr : AnsiString;
    property RemoteHost : AnsiString read GetRemoteHost Write SetRemoteHost;
    property RemotePort : Word read GetRemotePort write SetRemotePort;
    property Connected : Boolean read GetConnected;
    procedure Disconnect;
    function Connect : Boolean;
    //
    function WaitForData(WaitMilliseconds : Integer) : Boolean;
    //
    property OnConnect : TNotifyEvent read FOnConnect write SetOnConnect;
    property OnDisconnect : TNotifyEvent read FOnDisconnect write SetOnDisconnect;
    function BytesReceived : Int64;
    function BytesSent : Int64;
    property SocketError : Integer read FSocketError write SetSocketError;
    property LastCommunicationTime : TDateTime read FLastCommunicationTime;
  end;

  TNetTcpIpClientClass = class of TNetTcpIpClient;

  TBufferedNetTcpIpClient = class;

  TBufferedNetTcpIpClientThread = class(TPCThread)
    FBufferedNetTcpIpClient : TBufferedNetTcpIpClient;
  protected
    procedure BCExecute; override;
  public
    constructor Create(ABufferedNetTcpIpClient : TBufferedNetTcpIpClient);
  end;

  TBufferedNetTcpIpClient = class(TNetTcpIpClient)
  private
    FSendBuffer : TMemoryStream;
    FReadBuffer : TMemoryStream;
    FCritical : TPCCriticalSection;
    FLastReadTC : Cardinal;
    FBufferedNetTcpIpClientThread : TBufferedNetTcpIpClientThread;
  protected
    function DoWaitForDataInherited(WaitMilliseconds : Integer) : Boolean;
    procedure DoWaitForData(WaitMilliseconds : Integer; var HasData : Boolean); override;
  public
    constructor Create(AOwner : TComponent); override;
    destructor Destroy; override;
    procedure WriteBufferToSend(SendData : TStream);
    function ReadBufferLock : TMemoryStream;
    procedure ReadBufferUnlock;
    property LastReadTC : Cardinal read FLastReadTC;
  end;

  {$IFDEF Synapse}
  TNetTcpIpServer = class;
  TTcpIpServerListenerThread = class;

  TTcpIpSocketThread = class(TPCThread)
  private
    FSock: TTCPBlockSocket;
    FListenerThread : TTcpIpServerListenerThread;
  protected
    procedure BCExecute; override;
  public
    constructor Create(AListenerThread : TTcpIpServerListenerThread; ASocket : TSocket);
    destructor Destroy; override;
  end;

  TTcpIpServerListenerThread = class(TPCThread)
  private
    FNetTcpIpServerServer : TNetTcpIpServer;
    FServerSocket: TTCPBlockSocket;
    FTcpIpSocketsThread : TPCThreadList;
  protected
    procedure BCExecute; override;
  public
    constructor Create(ANetTcpIpServer : TNetTcpIpServer);
    destructor Destroy; override;
  end;
  {$ENDIF}

  TNetTcpIpServer = class(TObject)
  private
    {$IFDEF DelphiSockets}
    FTcpIpServer : TTcpServer;
    {$ENDIF}
    {$IFDEF Synapse}
    FTcpIpServer : TTcpIpServerListenerThread;
    FPort : Word;
    FActive : Boolean;
    {$ENDIF}
    FNetClients : TPCThreadList;
    FMaxConnections : Integer;
    FNetTcpIpClientClass : TNetTcpIpClientClass;
    function GetActive: Boolean;
    procedure SetPort(const Value: Word);  // When a connection is established to a new client, a TNetConnection is created (p2p)
    function GetPort: Word;
    procedure OnTcpServerAccept(Sender: TObject; ClientSocket: TTCPBlockSocket);
    procedure SetNetTcpIpClientClass(const Value: TNetTcpIpClientClass);
  protected
    procedure OnNewIncommingConnection(Sender : TObject; Client : TNetTcpIpClient); virtual;
    procedure SetActive(const Value: Boolean); virtual;
  public
    constructor Create; virtual;
    destructor Destroy; override;
    property Active : Boolean read GetActive write SetActive;
    property Port : Word read GetPort Write SetPort;
    property MaxConnections : Integer read FMaxConnections Write FMaxConnections;
    property NetTcpIpClientClass : TNetTcpIpClientClass read FNetTcpIpClientClass write SetNetTcpIpClientClass;
    function NetTcpIpClientsLock : TList;
    procedure NetTcpIpClientsUnlock;
    procedure WaitUntilNetTcpIpClientsFinalized;
  end;


implementation

uses
{$IFnDEF FPC}
  Windows,
{$ELSE}
  {LCLIntf, LCLType, LMessages,}
{$ENDIF}
  UConst, ULog;

{ TNetTcpIpClient }

function TNetTcpIpClient.BytesReceived: Int64;
begin
  {$IFDEF DelphiSockets}
  Result := FTcpBlockSocket.BytesReceived;
  {$ENDIF}
  {$IFDEF Synapse}
  Result := FBytesReceived;
  {$ENDIF}
end;

function TNetTcpIpClient.BytesSent: Int64;
begin
  {$IFDEF DelphiSockets}
  Result := FTcpBlockSocket.BytesSent;
  {$ENDIF}
  {$IFDEF Synapse}
  Result := FBytesSent;
  {$ENDIF}
end;

function TNetTcpIpClient.ClientRemoteAddr: AnsiString;
begin
  if Assigned(FTcpBlockSocket) then begin
    {$IFDEF DelphiSockets}
    Result := FTcpBlockSocket.RemoteHost+':'+FTcpBlockSocket.RemotePort;
    {$ENDIF}
    {$IFDEF Synapse}
    Result := FRemoteHost+':'+inttostr(FRemotePort);
    {$ENDIF}
  end else Result := 'NIL';
end;

function TNetTcpIpClient.Connect: Boolean;
begin
  {$IFDEF DelphiSockets}
  FSocketError := 0;
  Result := FTcpBlockSocket.Connect;
  {$ENDIF}
  {$IFDEF Synapse}
  FLock.Acquire;
  try
    try
      FTcpBlockSocket.Connect(FRemoteHost,IntToStr(FRemotePort));
      FConnected := FTcpBlockSocket.LastError=0;
      if (FConnected) then begin
        FRemoteHost := FTcpBlockSocket.GetRemoteSinIP;
        FRemotePort := FTcpBlockSocket.GetRemoteSinPort;
        DoOnConnect;
      end else TLog.NewLog(ltdebug,Classname,'Cannot connect to a server at: '+ClientRemoteAddr+' Reason: '+FTcpBlockSocket.GetErrorDescEx);
    except
      on E:Exception do begin
        SocketError := FTcpBlockSocket.LastError;
        TLog.NewLog(lterror,ClassName,'Error Connecting to '+ClientRemoteAddr+': '+FTcpBlockSocket.GetErrorDescEx);
        Disconnect;
      end;
    end;
  finally
    FLock.Release;
  end;
  Result := FConnected;
  {$ENDIF}
end;

constructor TNetTcpIpClient.Create(AOwner : TComponent);
begin
  inherited;
  FTcpBlockSocket := nil;
  FSocketError := 0;
  FLastCommunicationTime := 0;
  {$IFDEF DelphiSockets}
  FTcpBlockSocket := TTcpClient.Create(Nil);
  FTcpBlockSocket.OnConnect := OnConnect;
  FTcpBlockSocket.OnDisconnect := OnDisconnect;
  FTcpBlockSocket.OnError := TCustomIpClient_OnError;
  {$ENDIF}
  {$IFDEF Synapse}
  FLock := TPCCriticalSection.Create('TNetTcpIpClient_Lock');
  FTcpBlockSocket := TTCPBlockSocket.Create;
  FTcpBlockSocket.OnAfterConnect := OnConnect;
  FTcpBlockSocket.SocksTimeout := 5000; //Build 1.5.0 was 10000;
  FTcpBlockSocket.ConnectionTimeout := 5000; // Build 1.5.0 was default
  FRemoteHost := '';
  FRemotePort  := 0;
  FBytesReceived := 0;
  FBytesSent := 0;
  FConnected := False;
  {$ENDIF}
end;

destructor TNetTcpIpClient.Destroy;
begin
  Disconnect;
  {$IFDEF Synapse}  // Memory leak on 1.5.0
  FreeAndNil(FLock);
  {$ENDIF}
  inherited;
  FreeAndNil(FTcpBlockSocket);
  TLog.NewLog(ltdebug,ClassName,'Destroying Socket end');
end;

procedure TNetTcpIpClient.Disconnect;
begin
  {$IFDEF DelphiSockets}
  FTcpBlockSocket.Disconnect;
  {$ENDIF}
  {$IFDEF Synapse}
  FLock.Acquire;
  try
    if not FConnected then exit;
    FConnected := false;
    FTcpBlockSocket.CloseSocket;
  finally
    FLock.Release;
  end;
  if Assigned(FOnDisconnect) then FOnDisconnect(Self);
  {$ENDIF}
end;

procedure TNetTcpIpClient.DoOnConnect;
begin
  if (Assigned(FOnConnect)) then FOnConnect(Self);
end;

procedure TNetTcpIpClient.DoWaitForData(WaitMilliseconds: Integer; var HasData: Boolean);
Begin
  {$IFDEF DelphiSockets}
  FSocketError := 0;
  HasData := FTcpBlockSocket.WaitForData(WaitMilliseconds);
  {$ENDIF}
  {$IFDEF Synapse}
  FLock.Acquire;
  try
    try
      HasData := FTcpBlockSocket.CanRead(WaitMilliseconds);
    except
      on E:Exception do begin
        SocketError := FTcpBlockSocket.LastError;
        TLog.NewLog(lterror,ClassName,'Error WaitingForData from '+ClientRemoteAddr+': '+FTcpBlockSocket.GetErrorDescEx);
        Disconnect;
      end;
    end;
  finally
    FLock.Release;
  end;
  {$ENDIF}
end;

function TNetTcpIpClient.GetConnected: Boolean;
begin
  {$IFDEF DelphiSockets}
  Result := FTcpBlockSocket.Connected;
  {$ENDIF}
  {$IFDEF Synapse}
  Result := FConnected;
  {$ENDIF}
end;

function TNetTcpIpClient.GetRemoteHost: AnsiString;
begin
  {$IFDEF DelphiSockets}
  Result := FTcpBlockSocket.RemoteHost;
  {$ENDIF}
  {$IFDEF Synapse}
  Result := FRemoteHost;
  {$ENDIF}
end;

function TNetTcpIpClient.GetRemotePort: Word;
begin
  {$IFDEF DelphiSockets}
  Result := StrToIntDef(FTcpBlockSocket.RemotePort,0);
  {$ENDIF}
  {$IFDEF Synapse}
  Result := FRemotePort;
  {$ENDIF}
end;

function TNetTcpIpClient.ReceiveBuf(var Buf; BufSize: Integer): Integer;
begin
  {$IFDEF DelphiSockets}
  FSocketError := 0;
  Result := FTcpBlockSocket.ReceiveBuf(Buf,BufSize);
  {$ENDIF}
  {$IFDEF Synapse}
  FLock.Acquire;
  try
    try
      Result := FTcpBlockSocket.RecvBuffer(@Buf,BufSize);
      if (Result<0) or (FTcpBlockSocket.LastError<>0) then begin
        TLog.NewLog(ltInfo,ClassName,'Closing connection from '+ClientRemoteAddr+' (Receiving error): '+Inttostr(FTcpBlockSocket.LastError)+' '+FTcpBlockSocket.GetErrorDescEx);
        Disconnect;
      end else if Result>0 then inc(FBytesReceived,Result);
    except
      on E:Exception do begin
        SocketError := FTcpBlockSocket.LastError;
        TLog.NewLog(lterror,ClassName,'Exception receiving buffer from '+ClientRemoteAddr+' '+FTcpBlockSocket.GetErrorDescEx);
        Disconnect;
      end;
    end;
  finally
    FLock.Release;
  end;
  {$ENDIF}
  if Result>0 then FLastCommunicationTime := Now;
end;

function TNetTcpIpClient.SendStream(Stream: TStream): Int64;
var sp : Int64;
begin
  sp := Stream.Position;
  {$IFDEF DelphiSockets}
  FSocketError := 0;
  FTcpBlockSocket.SendStream(Stream);
  Result := Stream.Position - sp;
  {$ENDIF}
  {$IFDEF Synapse}
  FLock.Acquire;
  try
    try
      FTcpBlockSocket.SendStreamRaw(Stream);
      if FTcpBlockSocket.LastError<>0 then begin
        TLog.NewLog(ltInfo,ClassName,'Closing connection from '+ClientRemoteAddr+' (Sending error): '+Inttostr(FTcpBlockSocket.LastError)+' '+FTcpBlockSocket.GetErrorDescEx);
        Result := -1;
        Disconnect;
      end else begin
        Result := Stream.Position - sp;
        inc(FBytesSent,Result);
      end;
    except
      on E:Exception do begin
        SocketError := FTcpBlockSocket.LastError;
        TLog.NewLog(lterror,ClassName,'Exception sending stream to '+ClientRemoteAddr+': '+FTcpBlockSocket.GetErrorDescEx);
        Disconnect;
      end;
    end;
  finally
    FLock.Release;
  end;
  {$ENDIF}
  if Result>0 then FLastCommunicationTime := Now;
end;

procedure TNetTcpIpClient.SetOnConnect(const Value: TNotifyEvent);
begin
  FOnConnect := Value;
  {$IFDEF DelphiSockets}
  FTcpBlockSocket.OnConnect := FOnConnect;
  {$ENDIF}
end;

procedure TNetTcpIpClient.SetOnDisconnect(const Value: TNotifyEvent);
begin
  FOnDisconnect := Value;
  {$IFDEF DelphiSockets}
  FTcpBlockSocket.OnDisconnect := FOnDisconnect;
  {$ENDIF}
end;

procedure TNetTcpIpClient.SetRemoteHost(const Value: AnsiString);
begin
  {$IFDEF DelphiSockets}
  FTcpBlockSocket.RemoteHost := Value;
  {$ENDIF}
  {$IFDEF Synapse}
  FRemoteHost := Value;
  {$ENDIF}
end;

procedure TNetTcpIpClient.SetRemotePort(const Value: Word);
begin
  {$IFDEF DelphiSockets}
  FTcpBlockSocket.RemotePort := IntToStr(Value);
  {$ENDIF}
  {$IFDEF Synapse}
  FRemotePort := Value;
  {$ENDIF}
end;

procedure TNetTcpIpClient.SetSocketError(const Value: Integer);
begin
  FSocketError := Value;
  if Value<>0 then
    TLog.NewLog(ltdebug,Classname,'Error '+inttohex(SocketError,8)+' with connection to '+ClientRemoteAddr);
end;

{$IFDEF DelphiSockets}
procedure TNetTcpIpClient.TCustomIpClient_OnError(Sender: TObject; ASocketError: Integer);
begin
  SocketError := ASocketError;
  Disconnect;
end;
{$ENDIF}

function TNetTcpIpClient.WaitForData(WaitMilliseconds: Integer): Boolean;
begin
  DoWaitForData(WaitMilliseconds,Result);
end;

{ TBufferedNetTcpIpClientThread }

procedure TBufferedNetTcpIpClientThread.BCExecute;
var SendBuffStream : TStream;
  ReceiveBuffer : Array[0..4095] of byte;
  procedure DoReceiveBuf;
  var last_bytes_read : Integer;
    total_read, total_size : Int64;
    ms : TMemoryStream;
    lastpos : Int64;
  begin
    total_read := 0; total_size := 0;
    if FBufferedNetTcpIpClient.DoWaitForDataInherited(10) then begin
      last_bytes_read := 0;
      repeat
        if last_bytes_read<>0 then begin
          // This is to prevent a 4096 buffer transmission only... and a loop
          if not FBufferedNetTcpIpClient.DoWaitForDataInherited(10) then begin
            if FBufferedNetTcpIpClient.SocketError<>0 then FBufferedNetTcpIpClient.Disconnect
            else exit;
          end;
        end;

        last_bytes_read := FBufferedNetTcpIpClient.ReceiveBuf(ReceiveBuffer,sizeof(ReceiveBuffer));
        if (last_bytes_read>0) then begin
          ms := FBufferedNetTcpIpClient.ReadBufferLock;
          try
            FBufferedNetTcpIpClient.FLastReadTC := GetTickCount;
            lastpos := ms.Position;
            ms.Position := ms.Size;
            ms.Write(ReceiveBuffer,last_bytes_read);
            ms.Position := lastpos;
            inc(total_read,last_bytes_read);
            total_size := ms.Size;
          finally
            FBufferedNetTcpIpClient.ReadBufferUnlock;
          end;
        end;
      until (last_bytes_read<sizeof(ReceiveBuffer)) or (Terminated) or (not FBufferedNetTcpIpClient.Connected);
      if total_read>0 then TLog.NewLog(ltdebug,ClassName,Format('Received %d bytes. Buffer length: %d bytes',[total_read,total_size]));
    end else begin
      if FBufferedNetTcpIpClient.SocketError<>0 then FBufferedNetTcpIpClient.Disconnect;
    end;
  end;
  procedure DoSendBuf;
  begin
    FBufferedNetTcpIpClient.FCritical.Acquire;
    try
      if FBufferedNetTcpIpClient.FSendBuffer.Size>0 then begin
        SendBuffStream.Size := 0;
        SendBuffStream.CopyFrom(FBufferedNetTcpIpClient.FSendBuffer,0);
        FBufferedNetTcpIpClient.FSendBuffer.Size := 0;
      end;
    finally
      FBufferedNetTcpIpClient.FCritical.Release;
    end;
    if (SendBuffStream.Size>0) then begin
      SendBuffStream.Position := 0;
      FBufferedNetTcpIpClient.SendStream(SendBuffStream);
      TLog.NewLog(ltdebug,ClassName,Format('Sent %d bytes',[SendBuffStream.Size]));
      SendBuffStream.Size := 0;
    end;
  end;
begin
  SendBuffStream := TMemoryStream.Create;
  try
    while (not Terminated) do begin
      while (not Terminated) and (not FBufferedNetTcpIpClient.Connected) do sleep(100);
      if (FBufferedNetTcpIpClient.Connected) then begin
        // Receive data
        if (not Terminated) and (FBufferedNetTcpIpClient.Connected) then DoReceiveBuf;
        // Send Data
        if (not Terminated) and (FBufferedNetTcpIpClient.Connected) then DoSendBuf;
      end else FBufferedNetTcpIpClient.FLastReadTC := GetTickCount;
      // Sleep
      Sleep(10); // Slepp 10 is better than sleep 1
    end;
  finally
    SendBuffStream.Free;
  end;
end;

constructor TBufferedNetTcpIpClientThread.Create(
  ABufferedNetTcpIpClient: TBufferedNetTcpIpClient);
begin
  FBufferedNetTcpIpClient := ABufferedNetTcpIpClient;
  inherited Create(false);
end;

{ TBufferedNetTcpIpClient }

constructor TBufferedNetTcpIpClient.Create(AOwner: TComponent);
begin
  inherited;
  FLastReadTC := GetTickCount;
  FCritical := TPCCriticalSection.Create('TBufferedNetTcpIpClient_Critical');
  FSendBuffer := TMemoryStream.Create;
  FReadBuffer := TMemoryStream.Create;
  FBufferedNetTcpIpClientThread := TBufferedNetTcpIpClientThread.Create(Self);
end;

destructor TBufferedNetTcpIpClient.Destroy;
begin
  FBufferedNetTcpIpClientThread.Terminate;
  FBufferedNetTcpIpClientThread.WaitFor;
  FreeAndNil(FBufferedNetTcpIpClientThread);
  FreeAndNil(FCritical);
  FreeAndNil(FReadBuffer);
  FreeAndNil(FSendBuffer);
  inherited;
end;

procedure TBufferedNetTcpIpClient.DoWaitForData(WaitMilliseconds: Integer; var HasData: Boolean);
begin
  FCritical.Acquire;
  try
    if FReadBuffer.Size>0 then begin
      HasData := True;
      exit;
    end;
  finally
    FCritical.Release;
  end;
  inherited DoWaitForData(WaitMilliseconds,HasData);
end;

function TBufferedNetTcpIpClient.DoWaitForDataInherited(WaitMilliseconds : Integer) : Boolean;
begin
  inherited DoWaitForData(WaitMilliseconds,Result);
end;

function TBufferedNetTcpIpClient.ReadBufferLock: TMemoryStream;
begin
  FCritical.Acquire;
  Result := FReadBuffer;
end;

procedure TBufferedNetTcpIpClient.ReadBufferUnlock;
begin
  FCritical.Release;
end;

procedure TBufferedNetTcpIpClient.WriteBufferToSend(SendData: TStream);
var lastpos : Int64;
begin
  FCritical.Acquire;
  try
    lastpos := FSendBuffer.Position;
    FSendBuffer.Position := FSendBuffer.Size;
    SendData.Position := 0;
    FSendBuffer.CopyFrom(SendData,SendData.Size);
    FSendBuffer.Position := lastpos;
  finally
    FCritical.Release;
  end;
end;

{ TNetTcpIpServer }

constructor TNetTcpIpServer.Create;
begin
  FNetTcpIpClientClass := TNetTcpIpClient;
  FTcpIpServer := nil;
  FMaxConnections := 10;
  {$IFDEF DelphiSockets}
  FTcpIpServer := TTcpServer.Create(Nil);
  FTcpIpServer.OnAccept := OnTcpServerAccept;
  FTcpIpServer.ServerSocketThread.ThreadCacheSize := CT_MaxClientsConnected;
  {$ELSE}
  FActive := false;
  {$ENDIF}
  FNetClients := TPCThreadList.Create('TNetTcpIpServer_NetClients');
end;

destructor TNetTcpIpServer.Destroy;
begin
  Active := false;
  {$IFDEF DelphiSockets}
  FreeAndNil(FTcpIpServer);
  {$ENDIF}
  inherited;
  FreeAndNil(FNetClients);
end;

function TNetTcpIpServer.GetActive: Boolean;
begin
  {$IFDEF DelphiSockets}
  Result := FTcpIpServer.Active;
  {$ELSE}
  Result := Assigned(FTcpIpServer) and (FActive);
  {$ENDIF}
end;

function TNetTcpIpServer.GetPort: Word;
begin
  {$IFDEF DelphiSockets}
  Result := StrToIntDef(FTcpIpServer.LocalPort,0);
  {$ELSE}
  Result := FPort;
  {$ENDIF}
end;

function TNetTcpIpServer.NetTcpIpClientsLock: TList;
begin
  Result := FNetClients.LockList;
end;

procedure TNetTcpIpServer.NetTcpIpClientsUnlock;
begin
  FNetClients.UnlockList;
end;

procedure TNetTcpIpServer.OnNewIncommingConnection(Sender: TObject; Client: TNetTcpIpClient);
begin
  //
end;

procedure TNetTcpIpServer.OnTcpServerAccept(Sender: TObject; ClientSocket: TTCPBlockSocket);
var n : TNetTcpIpClient;
  oldSocket : TTCPBlockSocket;
begin
  {$IFDEF DelphiSockets}
  if FTcpIpServer.ServerSocketThread.ThreadCacheSize <> MaxConnections then
      FTcpIpServer.ServerSocketThread.ThreadCacheSize := MaxConnections;
  {$ENDIF}

  n := FNetTcpIpClientClass.Create(Nil);
  try
    {$IFDEF Synapse}
    n.FLock.Acquire;
    try
    {$ENDIF}
      oldSocket := n.FTcpBlockSocket;
      n.FTcpBlockSocket := ClientSocket;
      {$IFDEF Synapse}
      n.FConnected := True;
      n.RemoteHost := ClientSocket.GetRemoteSinIP;
      n.RemotePort := ClientSocket.GetRemoteSinPort;
      ClientSocket.SocksTimeout := 5000; //New 1.5.1
      ClientSocket.ConnectionTimeout := 5000; // New 1.5.1
      {$ENDIF}
    {$IFDEF Synapse}
    finally
      n.FLock.Release;
    end;
    {$ENDIF}
    FNetClients.Add(n);
    try
      OnNewIncommingConnection(Sender,n);
    finally
      FNetClients.Remove(n);
    end;
  finally
    n.FTcpBlockSocket := oldSocket;
    FreeAndNil(n);
  end;
end;

procedure TNetTcpIpServer.SetActive(const Value: Boolean);
begin
  {$IFDEF DelphiSockets}
  FTcpIpServer.Active := Value;
  {$ELSE}
  if Value then begin
    if (Assigned(FTcpIpServer)) then exit;
    FTcpIpServer := TTcpIpServerListenerThread.Create(Self);
    FActive := true;
  end else begin
    if (not Assigned(FTcpIpServer)) then exit;
    FActive := false;
    FTcpIpServer.Terminate;
    FTcpIpServer.WaitFor;
    FreeAndNil(FTcpIpServer);
  end;
  {$ENDIF}
end;

procedure TNetTcpIpServer.SetNetTcpIpClientClass(const Value: TNetTcpIpClientClass);
begin
  if FNetTcpIpClientClass=Value then exit;
  FNetTcpIpClientClass := Value;
  Active := false;
end;

procedure TNetTcpIpServer.SetPort(const Value: Word);
begin
  {$IFDEF DelphiSockets}
  FTcpIpServer.LocalPort := IntToStr(Value);
  {$ELSE}
  FPort := Value;
  {$ENDIF}
end;

procedure TNetTcpIpServer.WaitUntilNetTcpIpClientsFinalized;
var l : TList;
begin
  if Active then Active := false;
  Repeat
    l := FNetClients.LockList;
    try
      if (l.Count=0) then exit;
    finally
      FNetClients.UnlockList;
    end;
    sleep(10);
  Until false;
end;

{$IFDEF Synapse}
{ TTcpIpServerListenerThread }

procedure TTcpIpServerListenerThread.BCExecute;
var ClientSocket: TSocket;
    ClientThread: TTcpIpSocketThread;
    lSockets : TList;
    i : Integer;
begin
  FServerSocket.CreateSocket;
  if FServerSocket.LastError<>0 then begin
    TLog.NewLog(lterror,Classname,'Error initializing the socket: '+FServerSocket.GetErrorDescEx);
    exit;
  end;
  FServerSocket.Family := SF_IP4;
  FServerSocket.SetLinger(true,10000);
  FServerSocket.Bind('0.0.0.0',IntToStr(FNetTcpIpServerServer.Port));
  if FServerSocket.LastError<>0 then begin
    TLog.NewLog(lterror,Classname,'Cannot bind port '+IntToStr(FNetTcpIpServerServer.Port)+': '+FServerSocket.GetErrorDescEx);
    exit;
  end;
  FServerSocket.Listen;
  lSockets := TList.Create;
  try
    while (not Terminated) and (FNetTcpIpServerServer.Active) do begin
      if (FServerSocket.CanRead(100)) and (lSockets.Count<FNetTcpIpServerServer.MaxConnections) then begin
        ClientSocket := FServerSocket.Accept;
        if FServerSocket.LastError = 0 then begin
          ClientThread := TTcpIpSocketThread.Create(Self,ClientSocket);
          lSockets.Add(ClientThread);
          ClientThread.Suspended := false;
        end;
      end;
      // Clean finished threads
      for i := lSockets.Count - 1 downto 0 do begin
        ClientThread := TTcpIpSocketThread(lSockets[i]);
        if ClientThread.Terminated then begin
          lSockets.Delete(i);
          ClientThread.Free;
        end;
      end;
      // Wait
      sleep(10); // Sleep 10 is better than sleep 1
    end;
  finally
    // Finalize all threads
    for i := 0 to lSockets.Count - 1 do begin
      // Here we no wait until terminated...
      TTcpIpSocketThread(lSockets[i]).FListenerThread := nil;
      TTcpIpSocketThread(lSockets[i]).Terminate;
      TTcpIpSocketThread(lSockets[i]).WaitFor;
      TTcpIpSocketThread(lSockets[i]).Free;
    end;
    lSockets.free;
  end;
end;

constructor TTcpIpServerListenerThread.Create(ANetTcpIpServer: TNetTcpIpServer);
begin
  FServerSocket := TTCPBlockSocket.Create;
  FNetTcpIpServerServer := ANetTcpIpServer;
  FNetTcpIpServerServer.FTcpIpServer := Self;
  inherited Create(false);
end;

destructor TTcpIpServerListenerThread.Destroy;
begin
  FNetTcpIpServerServer.FTcpIpServer := nil;
  FServerSocket.Free;
  inherited;
end;

{ TTcpIpSocketThread }

procedure TTcpIpSocketThread.BCExecute;
begin
  if (not Terminated) and (Assigned(FSock)) and (Assigned(FListenerThread)) then
    FListenerThread.FNetTcpIpServerServer.OnTcpServerAccept(Self,FSock);
end;

constructor TTcpIpSocketThread.Create(AListenerThread: TTcpIpServerListenerThread; ASocket: TSocket);
begin
  FSock := TTCPBlockSocket.Create;
  FSock.Socket := ASocket;
  FListenerThread := AListenerThread;
  inherited Create(true);
end;

destructor TTcpIpSocketThread.Destroy;
begin
  try
    if FSock.Socket<>INVALID_SOCKET then begin
      FSock.CloseSocket;
    end;
  except
    on E:Exception do begin
      TLog.NewLog(lterror,ClassName,'Error closign socket: '+E.Message);
    end;
  end;
  try
    FreeAndNil(FSock);
  except
    on E:Exception do begin
      TLog.NewLog(lterror,ClassName,'Error destroying socket: '+E.Message);
    end;
  end;
  inherited;
end;

{$ENDIF}

end.
