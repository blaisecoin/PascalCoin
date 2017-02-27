{
  Copyright (c) 2016 by Albert Molina
  Copyright (c) 2017 by BlaiseCoin developers

  Distributed under the MIT software license, see the accompanying file LICENSE
  or visit http://www.opensource.org/licenses/mit-license.php.

  This unit is a part of BlaiseCoin, a P2P crypto-currency.
}

unit UNetProtocol;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface

Uses
{$IFnDEF FPC}
  Windows,
{$ELSE}
  {LCLIntf, LCLType, LMessages,}
{$ENDIF}
  UBlockChain, Classes, SysUtils, UAccounts, UThread,
  UCrypto, UTCPIP, SyncObjs;

{$I config.inc}

Const
  CT_MagicRequest = $0001;
  CT_MagicResponse = $0002;
  CT_MagicAutoSend = $0003;

  CT_NetOp_Hello = $0001;              // Sends my last operationblock + servers. Receive last operationblock + servers + same operationblock number of sender
  CT_NetOp_Error = $0002;
  CT_NetOp_Message = $0003;
  CT_NetOp_GetBlocks = $0010;
  CT_NetOp_GetOperationsBlock = $0005; // Sends from and to. Receive a number of OperationsBlock to check
  CT_NetOp_NewBlock = $0011;
  CT_NetOp_AddOperations = $0020;


  CT_NetError_InvalidProtocolVersion = $0001;
  CT_NetError_IPBlackListed = $0002;
  CT_NetError_InvalidDataBufferInfo = $0010;
  CT_NetError_InternalServerError = $0011;
  CT_NetError_InvalidNewAccount = $0012;

Type
  {
  Net Protocol:

  3 different types: Request, Response or Auto-send
  Request:   <Magic Net Identification (4b)> <request  (2b)> <operation (2b)> <0x0000 (2b)><request_id(4b)> <protocol info(4b) > <data_length(4b) > <request_data (data_length bytes)>
  Response:  <Magic Net Identification (4b)> <response (2b)> <operation (2b)> <error_code (2b)> <request_id(4b)> <protocol info(4b)> <data_length(4b)> <response_data (data_length bytes)>
  Auto-send: <Magic Net Identification (4b)> <autosend (2b)> <operation (2b)> <0x0000 (2b)> <0x00000000 (4b)> <protocol info(4b)> <data_length(4b)> <data (data_length bytes)>

  Min size: 4b+2b+2b+2b+4b+4b+4b = 22 bytes
  Max size: (depends on last 4 bytes) = 22..(2^32)-1
  }

  TNetTransferType = (ntp_unknown, ntp_request, ntp_response, ntp_autosend);

  TNetProtocolVersion = record
    protocol_version,
    protocol_available : Word;
  end;

  TNetHeaderData = record
    header_type : TNetTransferType;
    protocol : TNetProtocolVersion;
    operation : Word;
    request_id : Cardinal;
    buffer_data_length : Cardinal;
    //
    is_error : Boolean;
    error_code : Integer;
    error_text : AnsiString;
  end;

  TNetConnection = class;

  TNodeServerAddress = record
    ip : AnsiString;
    port : Word;
    last_connection : Cardinal;
    last_connection_by_server : Cardinal;
    //
    netConnection : TNetConnection;
    its_myself : Boolean;
    last_attempt_to_connect : TDateTime;
    total_failed_attemps_to_connect : Integer;
    is_blacklisted : Boolean; // Build 1.4.4
    BlackListText : String;
  end;
  TNodeServerAddressArray = array of TNodeServerAddress;
  PNodeServerAddress = ^TNodeServerAddress;

  TNetMessage_Hello = record
     last_operation : TOperationBlock;
     servers_address : array of TNodeServerAddress;
  end;

  TNetRequestRegistered = record
    NetClient : TNetConnection;
    Operation : Word;
    RequestId : Cardinal;
    SendTime : TDateTime;
  end;

  TNetStatistics = record
    ActiveConnections : Integer; // All connections wiht "connected" state
    ClientsConnections : Integer; // All clients connected to me like a server with "connected" state
    ServersConnections : Integer; // All servers where I'm connected
    ServersConnectionsWithResponse : Integer; // All servers where I'm connected and I've received data
    TotalConnections : Integer;
    TotalClientsConnections : Integer;
    TotalServersConnections : Integer;
    BytesReceived : Int64;
    BytesSend : Int64;
  end;

  TNetData = class;

  { TNetDataNotifyEventsThread ensures that notifications of TNetData object
    will be in main Thread calling a Synchronized method }
  TNetDataNotifyEventsThread = class(TPCThread)
  private
    FNetData: TNetData;
    FNotifyOnReceivedHelloMessage : Boolean;
    FNotifyOnStatisticsChanged : Boolean;
    FNotifyOnNetConnectionsUpdated : Boolean;
    FNotifyOnNodeServersUpdated : Boolean;
    FNotifyOnBlackListUpdated : Boolean;
  protected
    procedure SynchronizedNotify;
    procedure BCExecute; override;
  public
    constructor Create(ANetData : TNetData);
  end;

  TNetClientsDestroyThread = class(TPCThread)
  private
    FNetData : TNetData;
    FTerminatedAllConnections : Boolean;
  protected
    procedure BCExecute; override;
  public
    constructor Create(NetData : TNetData);
    procedure WaitForTerminatedAllConnections;
  end;

  TThreadCheckConnections = class(TPCThread)
  private
    FNetData : TNetData;
    FLastCheckTS : Cardinal;
  protected
    procedure BCExecute; override;
  public
    constructor Create(NetData : TNetData);
  end;

  TNetData = class(TComponent)
  private
    FNetDataNotifyEventsThread : TNetDataNotifyEventsThread;
    FNodePrivateKey : TECPrivateKey;
    FNetConnections : TPCThreadList;
    FNodeServersAddresses : TPCThreadList;
    FLastRequestId : Cardinal;
    FRegisteredRequests : TPCThreadList;
    FIsDiscoveringServers : Boolean;
    FIsGettingNewBlockChainFromClient : Boolean;
    FOnNetConnectionsUpdated: TNotifyEvent;
    FOnNodeServersUpdated: TNotifyEvent;
    FOnBlackListUpdated: TNotifyEvent;
    FThreadCheckConnections : TThreadCheckConnections;
    FOnReceivedHelloMessage: TNotifyEvent;
    FNetStatistics: TNetStatistics;
    FOnStatisticsChanged: TNotifyEvent;
    FMaxRemoteOperationBlock : TOperationBlock;
    FFixedServers : TNodeServerAddressArray;
    FNetClientsDestroyThread : TNetClientsDestroyThread;
    FNetConnectionsActive: Boolean;
    procedure IncStatistics(incActiveConnections, incClientsConnections, incServersConnections, incServersConnectionsWithResponse : Integer; incBytesReceived, incBytesSend : Int64);

    procedure SetNetConnectionsActive(const Value: Boolean);  protected
    procedure Notification(AComponent: TComponent; Operation: TOperation); override;
    function IndexOfNetClient(ListToSearch : TList; ip : AnsiString; port : Word; indexStart : Integer = 0) : Integer;
    procedure DeleteNetClient(List : TList; index : Integer);
    procedure CleanBlackList;
    procedure DiscoverServersTerminated(Sender : TObject);
  public
    class function HeaderDataToText(const HeaderData : TNetHeaderData) : AnsiString;
    class function ExtractHeaderInfo(buffer : TStream; var HeaderData : TNetHeaderData; DataBuffer : TStream; var IsValidHeaderButNeedMoreData : Boolean) : Boolean;
    class function OperationToText(operation : Word) : AnsiString;
    // Only 1 NetData
    class function NetData : TNetData;
    class function NetDataExists : Boolean;
    //
    constructor Create(AOwner : TComponent); override;
    destructor Destroy; override;
    function Bank : TPCBank;
    function NewRequestId : Cardinal;
    procedure RegisterRequest(Sender: TNetConnection; operation : Word; request_id : Cardinal);
    function UnRegisterRequest(Sender: TNetConnection; operation : Word; request_id : Cardinal) : Boolean;
    function PendingRequest(Sender : TNetConnection; var requests_data : AnsiString ) : Integer;
    procedure AddServer(NodeServerAddress : TNodeServerAddress);
    function IsBlackListed(const ip : AnsiString; port : Word) : Boolean;
    //
    procedure DiscoverFixedServersOnly(const FixedServers : TNodeServerAddressArray);
    //
    function ConnectionsCountAll : Integer;
    function ConnectionsCountServerClients : Integer;
    function ConnectionsCountClients : Integer;
    function GetConnection(index : Integer; var NetConnection : TNetConnection) : Boolean;
    function ConnectionsCount(CountOnlyNetClients : Boolean) : Integer;
    function Connection(index : Integer) : TNetConnection;
    function ConnectionExistsAndActive(ObjectPointer : TObject) : Boolean;
    function ConnectionExists(ObjectPointer : TObject) : Boolean;
    function ConnectionLock(Sender : TObject; ObjectPointer : TObject; MaxWaitMiliseconds : Cardinal) : Boolean;
    procedure ConnectionUnlock(ObjectPointer : TObject);
    function FindConnectionByClientRandomValue(Sender : TNetConnection) : TNetConnection;
    procedure DiscoverServers;
    procedure DisconnectClients;
    procedure GetNewBlockChainFromClient(Connection : TNetConnection; const why : String);
    property NodeServersAddresses : TPCThreadList read FNodeServersAddresses;
    property NetConnections : TPCThreadList read FNetConnections;
    property NetStatistics : TNetStatistics read FNetStatistics;
    property IsDiscoveringServers : Boolean read FIsDiscoveringServers;
    property IsGettingNewBlockChainFromClient : Boolean read FIsGettingNewBlockChainFromClient;
    property MaxRemoteOperationBlock : TOperationBlock read FMaxRemoteOperationBlock;
    property NodePrivateKey : TECPrivateKey read FNodePrivateKey;
    function GetValidNodeServers(OnlyWhereIConnected : Boolean; Max : Integer): TNodeServerAddressArray;
    property OnNetConnectionsUpdated : TNotifyEvent read FOnNetConnectionsUpdated write FOnNetConnectionsUpdated;
    property OnNodeServersUpdated : TNotifyEvent read FOnNodeServersUpdated write FOnNodeServersUpdated;
    property OnBlackListUpdated : TNotifyEvent read FOnBlackListUpdated write FOnBlackListUpdated;
    property OnReceivedHelloMessage : TNotifyEvent read FOnReceivedHelloMessage write FOnReceivedHelloMessage;
    property OnStatisticsChanged : TNotifyEvent read FOnStatisticsChanged write FOnStatisticsChanged;
    procedure NotifyNetConnectionUpdated;
    procedure NotifyNodeServersUpdated;
    procedure NotifyBlackListUpdated;
    procedure NotifyReceivedHelloMessage;
    procedure NotifyStatisticsChanged;
    property NetConnectionsActive : Boolean read FNetConnectionsActive write SetNetConnectionsActive;
  end;

  TNetConnection = class(TComponent)
  private
    FTcpIpClient : TNetTcpIpClient;
    FRemoteOperationBlock : TOperationBlock;
    FRemoteAccumulatedWork : UInt64;
    FLastDataReceivedTS : Cardinal;
    FLastDataSendedTS : Cardinal;
    FClientBufferRead : TStream;
    FNetLock : TPCCriticalSection;
    FIsWaitingForResponse : Boolean;
    FLastKnownTimestampDiff : Int64;
    FIsMyselfServer : Boolean;
    FClientPublicKey : TAccountKey;
    FCreatedTime: TDateTime;
    FClientAppVersion: AnsiString;
    FDoFinalizeConnection : Boolean;
    FNetProtocolVersion: TNetProtocolVersion;
    FAlertedForNewProtocolAvailable : Boolean;
    FHasReceivedData : Boolean;
    FIsDownloadingBlocks : Boolean;
    FRandomWaitSecondsSendHello : Cardinal;
    function GetConnected: Boolean;
    procedure SetConnected(const Value: Boolean);
    procedure TcpClient_OnConnect(Sender: TObject);
    procedure TcpClient_OnDisconnect(Sender: TObject);
    function DoSendAndWaitForResponse(operation: Word; RequestId: Integer; SendDataBuffer, ReceiveDataBuffer: TStream; MaxWaitTime : Cardinal; var HeaderData : TNetHeaderData) : Boolean;
    procedure DoProcessBuffer;
    procedure DoProcess_Hello(HeaderData : TNetHeaderData; DataBuffer: TStream);
    procedure DoProcess_Message(HeaderData : TNetHeaderData; DataBuffer: TStream);
    procedure DoProcess_GetBlocks_Request(HeaderData : TNetHeaderData; DataBuffer: TStream);
    procedure DoProcess_GetBlocks_Response(HeaderData : TNetHeaderData; DataBuffer: TStream);
    procedure DoProcess_GetOperationsBlock_Request(HeaderData : TNetHeaderData; DataBuffer: TStream);
    procedure DoProcess_NewBlock(HeaderData : TNetHeaderData; DataBuffer: TStream);
    procedure DoProcess_AddOperations(HeaderData : TNetHeaderData; DataBuffer: TStream);
    procedure SetClient(Const Value : TNetTcpIpClient);
    function ReadTcpClientBuffer(MaxWaitMiliseconds : Cardinal; var HeaderData : TNetHeaderData; BufferData : TStream) : Boolean;
    procedure DisconnectInvalidClient(ItsMyself : Boolean; Const why : AnsiString);
    function GetClient: TNetTcpIpClient;
  protected
    procedure Notification(AComponent: TComponent; Operation: TOperation); override;
    procedure Send(NetTranferType : TNetTransferType; operation, errorcode : Word; request_id : Integer; DataBuffer : TStream);
    procedure SendError(NetTranferType : TNetTransferType; operation, request_id : Integer; error_code : Integer; error_text : AnsiString);
  public
    constructor Create(AOwner : TComponent); override;
    destructor Destroy; override;
    function ConnectTo(ServerIP: String; ServerPort:Word) : Boolean;
    property Connected : Boolean read GetConnected write SetConnected;
    function Send_Hello(NetTranferType : TNetTransferType; request_id : Integer) : Boolean;
    function Send_NewBlockFound : Boolean;
    function Send_GetBlocks(StartAddress, quantity : Cardinal; var request_id : Cardinal) : Boolean;
    function Send_AddOperations(Operations : TOperationsHashTree) : Boolean;
    function Send_Message(Const TheMessage : AnsiString) : Boolean;
    property Client : TNetTcpIpClient read GetClient;
    function ClientRemoteAddr : AnsiString;
    //
    property NetProtocolVersion : TNetProtocolVersion read FNetProtocolVersion;
    //
    property IsMyselfServer : Boolean read FIsMyselfServer;
    property CreatedTime : TDateTime read FCreatedTime;
    property ClientAppVersion : AnsiString read FClientAppVersion write FClientAppVersion;
    procedure FinalizeConnection;
  end;

  TNetClient = class;
  TNetClientThread = class(TPCThread)
  private
    FNetClient : TNetClient;
  protected
    procedure BCExecute; override;
  public
    constructor Create(NetClient : TNetClient; AOnTerminateThread : TNotifyEvent);
  end;

  TNetClient = class(TNetConnection)
  private
    FNetClientThread : TNetClientThread;
    procedure OnNetClientThreadTerminated(Sender : TObject);
  public
    constructor Create(AOwner : TComponent); override;
    destructor Destroy; override;
  end;

  TNetServerClient = class(TNetConnection);

  TNetServer = class(TNetTcpIpServer)
  private
  protected
    procedure OnNewIncommingConnection(Sender : TObject; Client : TNetTcpIpClient); override;
    procedure SetActive(const Value: Boolean); override;
  public
    constructor Create; override;
  end;

  TThreadDiscoverConnection = class(TPCThread)
    FNodeServerAddress : TNodeServerAddress;
  protected
    procedure BCExecute; override;
  public
    constructor Create(NodeServerAddress: TNodeServerAddress; NotifyOnTerminate : TNotifyEvent);
  end;

  TThreadGetNewBlockChainFromClient = class(TPCThread)
  protected
    procedure BCExecute; override;
  end;


const
  CT_TNodeServerAddress_NUL : TNodeServerAddress = (ip:'';port:0;last_connection:0;last_connection_by_server:0; netConnection:nil;its_myself:false;last_attempt_to_connect:0;total_failed_attemps_to_connect:0;is_blacklisted:false;BlackListText:'');
  CT_TNetStatistics_NUL : TNetStatistics = (ActiveConnections:0;ClientsConnections:0;ServersConnections:0;ServersConnectionsWithResponse:0;TotalConnections:0;TotalClientsConnections:0;TotalServersConnections:0;BytesReceived:0;BytesSend:0);

implementation

uses
  UConst, ULog, UStreamOp, UNode, UTime, UECIES;

const
  CT_NetTransferType : array[TNetTransferType] of AnsiString = ('Unknown', 'Request', 'Response', 'Autosend');
  CT_NetHeaderData : TNetHeaderData = (header_type:ntp_unknown;protocol:(protocol_version:0;protocol_available:0);operation:0;request_id:0;buffer_data_length:0;is_error:false;error_code:0;error_text:'');

{ TNetData }

var
  _NetData : TNetData = nil;

type
  PNetRequestRegistered = ^TNetRequestRegistered;

function SortNodeServerAddress(Item1, Item2: Pointer): Integer;
var P1, P2 : PNodeServerAddress;
Begin
  P1 := Item1;
  P2 := Item2;
  Result := AnsiCompareText(P1.ip, P2.ip);
  if Result = 0 then
    Result := P1.port - P2.port;
End;

constructor TNetData.Create;
begin
  TLog.NewLog(ltInfo, ClassName, 'TNetData.Create');
  FNetConnectionsActive := true;
  SetLength(FFixedServers, 0);
  FMaxRemoteOperationBlock := CT_OperationBlock_NUL;
  FNetStatistics := CT_TNetStatistics_NUL;
  FOnStatisticsChanged := nil;
  FOnNetConnectionsUpdated := nil;
  FOnNodeServersUpdated := nil;
  FOnBlackListUpdated := nil;
  FOnReceivedHelloMessage := nil;
  FIsDiscoveringServers := false;
  FRegisteredRequests := TPCThreadList.Create('TNetData_RegisteredRequests');
  FNodeServersAddresses := TPCThreadList.Create('TNetData_NodeServersAddresses');
  FLastRequestId := 0;
  FNetConnections := TPCThreadList.Create('TNetData_NetConnections');
  FIsGettingNewBlockChainFromClient := false;
  FNodePrivateKey := TECPrivateKey.Create;
  FNodePrivateKey.GenerateRandomPrivateKey(CT_Default_EC_OpenSSL_NID);
  FThreadCheckConnections := TThreadCheckConnections.Create(Self);
  FNetDataNotifyEventsThread := TNetDataNotifyEventsThread.Create(Self);
  FNetClientsDestroyThread := TNetClientsDestroyThread.Create(Self);
  if not Assigned(_NetData) then
    _NetData := Self;
end;

destructor TNetData.Destroy;
var
  l : TList;
  i : Integer;
  tdc : TThreadDiscoverConnection;
begin
  TLog.NewLog(ltInfo, ClassName, 'TNetData.Destroy START');
  FOnStatisticsChanged := nil;
  FOnNetConnectionsUpdated := nil;
  FOnNodeServersUpdated := nil;
  FOnBlackListUpdated := nil;
  FOnReceivedHelloMessage := nil;

  // First destroy ThreadCheckConnections to prevent a call to "DiscoverServers"
  FThreadCheckConnections.Terminate;
  FThreadCheckConnections.WaitFor;
  FreeAndNil(FThreadCheckConnections);

  // Now finish all DiscoverConnection threads
  repeat
    tdc := TThreadDiscoverConnection( TPCThreadClass.GetThreadByClass(TThreadDiscoverConnection, nil) );
    if Assigned(tdc) then
    begin
      tdc.FreeOnTerminate := false;
      tdc.Terminate;
      tdc.WaitFor;
      tdc.Free;
    end;
  until not Assigned(tdc);

  // Closing connections
  l := FNetConnections.LockList;
  try
    for i := 0 to l.Count - 1 do
    begin
      TNetConnection(l[i]).Connected := false;
      TNetConnection(l[i]).FinalizeConnection;
    end;
  finally
    FNetConnections.UnlockList;
  end;


  FNetClientsDestroyThread.WaitForTerminatedAllConnections;
  FNetClientsDestroyThread.Terminate;
  FNetClientsDestroyThread.WaitFor;
  FreeAndNil(FNetClientsDestroyThread);

  CleanBlackList;
  l := FNodeServersAddresses.LockList;
  try
    while (l.Count > 0) do
      DeleteNetClient(l, l.Count-1);
  finally
    FNodeServersAddresses.UnlockList;
    FreeAndNil(FNodeServersAddresses);
  end;
  FreeAndNil(FNetConnections);
  FreeAndNil(FNodePrivateKey);
  FNetDataNotifyEventsThread.Terminate;
  FNetDataNotifyEventsThread.WaitFor;
  FreeAndNil(FNetDataNotifyEventsThread);
  SetLength(FFixedServers, 0);
  FreeAndNil(FRegisteredRequests);
  inherited;
  if (_NetData = Self) then
    _NetData := nil;
  TLog.NewLog(ltInfo, ClassName, 'TNetData.Destroy END');
end;

procedure TNetData.AddServer(NodeServerAddress: TNodeServerAddress);
var P : PNodeServerAddress;
  i : Integer;
  l : TList;
begin
  if trim(NodeServerAddress.ip) = '' then
    exit;
  l := FNodeServersAddresses.LockList;
  try
    i := IndexOfNetClient(l, NodeServerAddress.ip, NodeServerAddress.port);
    if i >= 0 then
    begin
      P := PNodeServerAddress(l[i]);
      if NodeServerAddress.last_connection > P^.last_connection then
        P^.last_connection := NodeServerAddress.last_connection;
      if NodeServerAddress.last_connection_by_server > P^.last_connection_by_server then
        P^.last_connection_by_server := NodeServerAddress.last_connection_by_server;
      if NodeServerAddress.last_attempt_to_connect > P^.last_attempt_to_connect then
        P^.last_attempt_to_connect := NodeServerAddress.last_attempt_to_connect;
      exit;
    end;
    New(P);
    P^ := NodeServerAddress;
    l.Add(P);
    l.Sort(SortNodeServerAddress);
    TLog.NewLog(ltdebug, Classname, 'Adding new server: ' + NodeServerAddress.ip + ':' + Inttostr(NodeServerAddress.port));
  finally
    FNodeServersAddresses.UnlockList;
  end;
  NotifyNodeServersUpdated;
end;

function TNetData.Bank: TPCBank;
begin
  Result := TNode.Node.Bank;
end;

procedure TNetData.CleanBlackList;
var
  P : PNodeServerAddress;
  i, n : Integer;
  l : TList;
begin
  // This procedure cleans old blacklisted IPs
  n := 0;
  l := FNodeServersAddresses.LockList;
  try
    for i := l.Count - 1 downto 0 do
    begin
      P := l[i];
      // Is an old blacklisted IP? (More than 1 hour)
      if (P^.is_blacklisted) and ((P^.last_connection + (60*60)) < (UnivDateTimeToUnix(DateTime2UnivDateTime(now)))) then
      begin
        l.Delete(i);
        Dispose(P);
        inc(n);
      end;
    end;
  finally
    FNodeServersAddresses.UnlockList;
  end;
  if (n > 0) then
    NotifyBlackListUpdated;
end;

function TNetData.Connection(index: Integer): TNetConnection;
var l : TList;
begin
  l := FNetConnections.LockList;
  try
    Result := TNetConnection( l[index] );
  finally
    FNetConnections.UnlockList;
  end;
end;

function TNetData.ConnectionExists(ObjectPointer: TObject): Boolean;
var
  i : Integer;
  l : TList;
begin
  Result := false;
  l := FNetConnections.LockList;
  try
    for i := 0 to l.Count - 1 do
    begin
      if TObject(l[i]) = ObjectPointer then
      begin
        Result := true;
        exit;
      end;
    end;
  finally
    FNetConnections.UnlockList;
  end;
end;

function TNetData.ConnectionExistsAndActive(ObjectPointer: TObject): Boolean;
var
  i : Integer;
  l : TList;
begin
  Result := false;
  l := FNetConnections.LockList;
  try
    for i := 0 to l.Count - 1 do
    begin
      if TObject(l[i]) = ObjectPointer then
      begin
        Result := (TNetConnection(ObjectPointer).Connected);
        exit;
      end;
    end;
  finally
    FNetConnections.UnlockList;
  end;
end;

function TNetData.ConnectionLock(Sender : TObject; ObjectPointer: TObject; MaxWaitMiliseconds : Cardinal) : Boolean;
var
  i : Integer;
  l : TList;
begin
  Result := false;
  l := FNetConnections.LockList;
  try
    for i := 0 to l.Count - 1 do
    begin
      if TObject(l[i]) = ObjectPointer then
      begin
        Result := TPCThread.TryProtectEnterCriticalSection(Sender, MaxWaitMiliseconds, TNetConnection(l[i]).FNetLock);
        exit;
      end;
    end;
  finally
    FNetConnections.UnlockList;
  end;
end;

function TNetData.ConnectionsCount(CountOnlyNetClients : Boolean): Integer;
var
  i : Integer;
  l : TList;
begin
  l := FNetConnections.LockList;
  try
    if CountOnlyNetClients then
    begin
      Result := 0;
      for i := 0 to l.Count - 1 do
      begin
        if TObject(l[i]) is TNetClient then
          inc(Result);
      end;
    end
    else
      Result := l.Count;
  finally
    FNetConnections.UnlockList;
  end;
end;

function TNetData.ConnectionsCountAll: Integer;
var l : TList;
begin
  l := FNetConnections.LockList;
  try
    Result := l.Count;
  finally
    FNetConnections.UnlockList;
  end;
end;

function TNetData.ConnectionsCountClients: Integer;
var l : TList; i : Integer;
begin
  Result := 0;
  l := FNetConnections.LockList;
  try
    for i := 0 to l.Count - 1 do
    begin
      if TObject(l[i]) is TNetClient then
        inc(Result);
    end;
  finally
    FNetConnections.UnlockList;
  end;
end;

function TNetData.ConnectionsCountServerClients: Integer;
var l : TList; i : Integer;
begin
  Result := 0;
  l := FNetConnections.LockList;
  try
    for i := 0 to l.Count - 1 do
    begin
      if TObject(l[i]) is TNetServerClient then
        inc(Result);
    end;
  finally
    FNetConnections.UnlockList;
  end;
end;

procedure TNetData.ConnectionUnlock(ObjectPointer: TObject);
var
  i : Integer;
  l : TList;
begin
  l := FNetConnections.LockList;
  try
    for i := 0 to l.Count - 1 do
    begin
      if TObject(l[i]) = ObjectPointer then
      begin
        TNetConnection(l[i]).FNetLock.Release;
        exit;
      end;
    end;
  finally
    FNetConnections.UnlockList;
  end;
end;

procedure TNetData.DeleteNetClient(List: TList; index: Integer);
var P : PNodeServerAddress;
begin
  P := List.Items[index];
  List.Delete(index);
  Dispose(P);
end;

procedure TNetData.DisconnectClients;
var
  i : Integer;
  l : TList;
begin
  l := FNetConnections.LockList;
  try
    for i := l.Count - 1 downto 0 do
    begin
      if TObject(l[i]) is TNetClient then
      begin
        TNetClient(l[i]).Connected := false;
        TNetClient(l[i]).FinalizeConnection;
      end;
    end;
  finally
    FNetConnections.UnlockList;
  end;
end;

procedure TNetData.DiscoverFixedServersOnly(const FixedServers: TNodeServerAddressArray);
var
  i : Integer;
  l : TList;
begin
  l := FNodeServersAddresses.LockList;
  try
    SetLength(FFixedServers, length(FixedServers));
    for i := low(FixedServers) to high(FixedServers) do
    begin
      FFixedServers[i] := FixedServers[i];
    end;
    for i := low(FixedServers) to high(FixedServers) do
    begin
      AddServer(FixedServers[i]);
    end;
  finally
    FNodeServersAddresses.UnlockList;
  end;
end;

procedure TNetData.DiscoverServers;
  procedure sw(l : TList);
  var i, j, x, y : Integer;
  begin
    if l.Count <= 1 then
      exit;
    j := Random(l.Count)*3;
    for i := 0 to j do
    begin
      x := Random(l.Count);
      y := Random(l.Count);
      if x <> y then
        l.Exchange(x, y);
    end;
  end;
var
  P : PNodeServerAddress;
  i, j, k : Integer;
  l, lns : TList;
  tdc : TThreadDiscoverConnection;
  canAdd : Boolean;
begin
  if not FNetConnectionsActive then
    exit;
  if TPCThread.ThreadClassFound(TThreadDiscoverConnection, nil) >= 0 then
  begin
    TLog.NewLog(ltInfo, ClassName, 'Already discovering servers...');
    exit;
  end;
  CleanBlackList;
  if NetStatistics.ClientsConnections > 0 then
  begin
    j := CT_MinServersConnected - NetStatistics.ServersConnectionsWithResponse;
  end else
  begin
    j := CT_MaxServersConnected - NetStatistics.ServersConnectionsWithResponse;
  end;
  if j <= 0 then exit;
  TLog.NewLog(ltDebug, Classname, 'Discover servers start process searching up to ' + inttostr(j) + ' servers');
  // can discover up to j servers
  l := TList.Create;
  try
    lns := FNodeServersAddresses.LockList;
    try
      for i := 0 to lns.Count-1 do
      begin
        P := lns[i];
        if (not Assigned(P.netConnection)) and (not IsBlackListed(P^.ip, P^.port)) and (not P^.its_myself) and
          ((P^.last_attempt_to_connect = 0) or ((P^.last_attempt_to_connect + EncodeTime(0, 3, 0, 0) < now))) and
          ((P^.total_failed_attemps_to_connect < 3) or (P^.last_attempt_to_connect + EncodeTime(0, 10, 0, 0) < now)) then
        begin
          if Length(FFixedServers) > 0 then
          begin
            canAdd := false;
            for k := low(FFixedServers) to high(FFixedServers) do
            begin
              if (FFixedServers[k].ip = P^.ip) and
                 ((FFixedServers[k].port = P.port)) then
              begin
                canAdd := true;
                break;
              end;
            end;
          end
          else
            canAdd := true;
          if canAdd then
            l.Add(P);
        end;
      end;
      if l.Count <= 0 then
        exit;
      sw(l);
      if j >= l.Count then
        j := l.Count-1;
      TLog.NewLog(ltDebug, Classname, 'Start discovering up to ' + inttostr(j + 1) + ' servers... (max:' + inttostr(l.count) + ')');
      //
      for i := 0 to j do
      begin
        FIsDiscoveringServers := true;
        P := PNodeServerAddress(l[i]);
        tdc := TThreadDiscoverConnection.Create(P^, DiscoverServersTerminated);
      end;
    finally
      FNodeServersAddresses.UnlockList;
    end;
  finally
    l.Free;
  end;
end;

procedure TNetData.DiscoverServersTerminated(Sender: TObject);
begin
  NotifyNodeServersUpdated;
  if TPCThread.ThreadClassFound(TThreadDiscoverConnection, Nil) >= 0 then
    exit;
  FIsDiscoveringServers := false;
  // if here, discover servers finished, so we can try to get/receive data
  TLog.NewLog(ltDebug, Classname, Format('Discovering servers finished. Now we have %d active connections and %d connections to other servers',
    [ConnectionsCount(false), ConnectionsCount(true)]));
  if TPCThread.ThreadClassFound(TThreadGetNewBlockChainFromClient, nil) >= 0 then
    exit;
  TThreadGetNewBlockChainFromClient.Create(false).FreeOnTerminate := true;
end;

class function TNetData.ExtractHeaderInfo(buffer : TStream; var HeaderData : TNetHeaderData; DataBuffer : TStream; var IsValidHeaderButNeedMoreData : Boolean) : Boolean;
var lastp : Integer;
  c : Cardinal;
  w : Word;
begin
  HeaderData := CT_NetHeaderData;
  Result := false;
  IsValidHeaderButNeedMoreData := false;
  lastp := buffer.Position;
  try
    if buffer.Size-buffer.Position < 22 then exit;
    buffer.Read(c, 4);
    if (c <> CT_MagicNetIdentification) then exit;
    buffer.Read(w, 2);
    case w of
      CT_MagicRequest  : HeaderData.header_type := ntp_request;
      CT_MagicResponse : HeaderData.header_type := ntp_response;
      CT_MagicAutoSend : HeaderData.header_type := ntp_autosend;
    else
      HeaderData.header_type := ntp_unknown;
      exit;
    end;
    buffer.Read(HeaderData.operation, 2);
    buffer.Read(HeaderData.error_code, 2);
    buffer.Read(HeaderData.request_id, 4);
    buffer.Read(HeaderData.protocol.protocol_version, 2);
    buffer.Read(HeaderData.protocol.protocol_available, 2);
    buffer.Read(c, 4);
    DataBuffer.Size := 0;
    if buffer.Size - buffer.Position < c then
    begin
      IsValidHeaderButNeedMoreData := true;
      exit;
    end;
    DataBuffer.CopyFrom(buffer, c);
    DataBuffer.Position := 0;
    HeaderData.buffer_data_length := c;
    //
    if HeaderData.header_type = ntp_response then
    begin
      HeaderData.is_error := HeaderData.error_code <> 0;
      if HeaderData.is_error then
      begin
        TStreamOp.ReadAnsiString(DataBuffer, HeaderData.error_text);
      end;
    end else
    begin
      HeaderData.is_error := HeaderData.error_code <> 0;
      if HeaderData.is_error then
      begin
        TStreamOp.ReadAnsiString(DataBuffer, HeaderData.error_text);
      end;
    end;
    if (HeaderData.is_error) then
    begin
      TLog.NewLog(lterror, Classname, 'Response with error (' + IntToHex(HeaderData.error_code, 4) + '): ' + HeaderData.error_text + ' ...on '+
        'operation: ' + OperationToText(HeaderData.operation) + ' id: ' + Inttostr(HeaderData.request_id));
    end;
    Result := true;
  finally
    if not Result then
      buffer.Position := lastp;
  end;
end;

function TNetData.FindConnectionByClientRandomValue(Sender: TNetConnection): TNetConnection;
var l : TList;
  i : Integer;
begin
  l := FNetConnections.LockList;
  try
    for i := 0 to L.Count - 1 do
    begin
      Result := TNetConnection( l[i] );
      if TAccountComp.Equal(Result.FClientPublicKey, Sender.FClientPublicKey) and (Sender <> Result) then
        exit;
    end;
  finally
    FNetConnections.UnlockList;
  end;
  Result := nil;
end;

function TNetData.GetConnection(index: Integer; var NetConnection : TNetConnection) : Boolean;
var l : TList;
begin
  Result := false; NetConnection := nil;
  l := FNetConnections.LockList;
  try
    if (index >= 0) and (index < l.Count) then
    begin
      NetConnection := TNetConnection( l[index] );
      Result := true;
      exit;
    end;
  finally
    FNetConnections.UnlockList;
  end;
end;

procedure TNetData.GetNewBlockChainFromClient(Connection: TNetConnection; const Why : String);
Const CT_LogSender = 'GetNewBlockChainFromClient';

  function Do_GetOperationsBlock(AssignToBank : TPCBank; block_start, block_end, MaxWaitMilliseconds : Cardinal; OnlyOperationBlock : Boolean; BlocksList : TList) : Boolean;
  var
    SendData, ReceiveData : TMemoryStream;
    headerdata : TNetHeaderData;
    op : TPCOperationsComp;
    request_id, opcount, i : Cardinal;
    errors : AnsiString;
    noperation : Integer;
  begin
    Result := false;
    BlocksList.Count := 0;
    if (Connection.FRemoteOperationBlock.block < block_end) then block_end := Connection.FRemoteOperationBlock.block;
    // First receive operations from
    SendData := TMemoryStream.Create;
    ReceiveData := TMemoryStream.Create;
    try
      if OnlyOperationBlock then
      begin
        noperation := CT_NetOp_GetOperationsBlock;
      end else
      begin
        noperation := CT_NetOp_GetBlocks;
      end;
      TLog.NewLog(ltdebug, CT_LogSender, Format('Sending %s from block %d to %d (Total: %d)',
        [TNetData.OperationToText(noperation), block_start, block_end, block_end-block_start + 1]));
      SendData.Write(block_start, 4);
      SendData.Write(block_end, 4);
      request_id := TNetData.NetData.NewRequestId;
      if Connection.DoSendAndWaitForResponse(noperation, request_id, SendData, ReceiveData, MaxWaitMilliseconds, headerdata) then
      begin
        if HeaderData.is_error then exit;
        if ReceiveData.Read(opcount, 4) < 4 then exit; // Error in data
        i := 0;
        while (i < opcount) do
        begin
          // decode data
          op := TPCOperationsComp.Create(AssignToBank);
          if op.LoadBlockFromStream(ReceiveData, errors) then
          begin
            BlocksList.Add(op);
          end else
          begin
            TLog.NewLog(lterror, CT_LogSender, Format('Error reading OperationBlock from received stream %d/%d: %s', [i + 1, opcount, errors]));
            op.free;
            break;
          end;
          inc(i);
        end;
        Result := true;
      end else
      begin
        TLog.NewLog(lterror, CT_LogSender, Format('No received response after waiting %d request id %d operation %s', [MaxWaitMilliseconds, request_id, TNetData.OperationToText(noperation)]));
      end;
    finally
      SendData.Free;
      ReceiveData.free;
    end;
  end;

  function Do_GetOperationBlock(block, MaxWaitMilliseconds : Cardinal; var OperationBlock : TOperationBlock) : Boolean;
  var
    BlocksList : TList;
    i : Integer;
  begin
    OperationBlock := CT_OperationBlock_NUL;
    BlocksList := TList.Create;
    try
      Result := Do_GetOperationsBlock(TNode.Node.Bank, block, block, MaxWaitMilliseconds, false, BlocksList);
      if (Result) and (BlocksList.Count = 1) then
      begin
        OperationBlock := TPCOperationsComp(BlocksList[0]).OperationBlock;
      end;
    finally
      for i := 0 to BlocksList.Count - 1 do TPCOperationsComp(BlocksList[i]).Free;
      BlocksList.Free;
    end;
  end;

  function FindLastSameBlockByOperationsBlock(min, max : Cardinal; var OperationBlock : TOperationBlock) : Boolean;
  var i : Integer;
    ant_nblock : Int64;
    myops : TPCOperationsComp;
    auxBlock : TOperationBlock;
    distinctmax, distinctmin : Cardinal;
    BlocksList : TList;
  begin
    Result := false;
    OperationBlock := CT_OperationBlock_NUL;
    repeat
      BlocksList := TList.Create;
      try
        if not Do_GetOperationsBlock(nil, min, max, 5000, true, BlocksList) then
          exit;
        distinctmin := min;
        distinctmax := max;
        myops := TPCOperationsComp.Create(TNode.Node.Bank);
        try
          ant_nblock := -1;
          for i := 0 to BlocksList.Count - 1 do begin
            auxBlock := TPCOperationsComp(BlocksList[i]).OperationBlock;
            // Protection of invalid clients:
            if (auxBlock.block < min) or (auxBlock.block > max) or (auxBlock.block = ant_nblock) then
            begin
              Connection.DisconnectInvalidClient(false, 'Invalid response... ' + inttostr(min) + ' < ' + inttostr(auxBlock.block) + ' < ' + inttostr(max) + ' ant:' + inttostr(ant_nblock));
              exit;
            end;
            ant_nblock := auxBlock.block;
            //
            if not TNode.Node.Bank.LoadOperations(myops, auxBlock.block) then
              exit;

            if ((myops.OperationBlock.proof_of_work = auxBlock.proof_of_work) and (myops.OperationBlock.nonce = auxBlock.nonce)) then
            begin
              distinctmin := auxBlock.block;
              OperationBlock := auxBlock;
            end else
            begin
              if auxBlock.block <= distinctmax then
                distinctmax := auxBlock.block-1;
            end;
          end;
        finally
          myops.Free;
        end;
        min := distinctmin;
        max := distinctmax;
      finally
        for i := 0 to BlocksList.Count - 1 do
        begin
          TPCOperationsComp(BlocksList[i]).Free;
        end;
        BlocksList.Free;
      end;
    until (distinctmin = distinctmax);
    Result := (OperationBlock.proof_of_work <> CT_OperationBlock_NUL.proof_of_work);
  end;

  function GetNewBank(start_block : Int64) : Boolean;
  var
    BlocksList : TList;
    i : Integer;
    OpComp, OpExecute : TPCOperationsComp;
    newBlock : TBlockAccount;
    errors : AnsiString;
    start : Cardinal;
    finished : Boolean;
    Bank : TPCBank;
    ms : TMemoryStream;
    IsAScam : Boolean;
  begin
    IsAScam := false;
    TLog.NewLog(ltdebug, CT_LogSender, Format('GetNewBank(new_start_block:%d)', [start_block]));
    Bank := TPCBank.Create(Nil);
    try
      Bank.StorageClass := TNode.Node.Bank.StorageClass;
      Bank.Storage.Orphan := TNode.Node.Bank.Storage.Orphan;
      Bank.Storage.ReadOnly := true;
      Bank.Storage.CopyConfiguration(TNode.Node.Bank.Storage);
      if start_block >= 0 then
      begin
        // Restore a part
        Bank.DiskRestoreFromOperations(start_block-1);
        start := start_block;
      end else
      begin
        start := 0;
        start_block := 0;
      end;
      Bank.Storage.Orphan := FormatDateTime('yyyymmddhhnnss', DateTime2UnivDateTime(now));
      Bank.Storage.ReadOnly := false;
      // Receive new blocks:
      finished := false;
      repeat
        BlocksList := TList.Create;
        try
          finished := not Do_GetOperationsBlock(Bank, start, start + 50, 5000, false, BlocksList);
          i := 0;
          while (i < BlocksList.Count) and (not finished) do
          begin
            OpComp := TPCOperationsComp(BlocksList[i]);
            ms := TMemoryStream.Create;
            OpExecute := TPCOperationsComp.Create(Bank);
            try
              OpComp.SaveBlockToStream(false, ms);
              ms.Position := 0;
              OpExecute.LoadBlockFromStream(ms, errors);
              if Bank.AddNewBlockChainBlock(OpExecute, newBlock, errors) then
              begin
                inc(i);
              end else
              begin
                TLog.NewLog(lterror, CT_LogSender, 'Error creating new bank with client Operations. Block:' + TPCOperationsComp.OperationBlockToText(OpExecute.OperationBlock) + ' Error:' + errors);
                // Add to blacklist !
                Connection.DisconnectInvalidClient(false, 'Invalid BlockChain on Block ' + TPCOperationsComp.OperationBlockToText(OpExecute.OperationBlock) + ' with errors:' + errors);
                finished := true;
                IsAScam := true;
                break;
              end;
            finally
              ms.Free;
              OpExecute.Free;
            end;
          end;
        finally
          for i := 0 to BlocksList.Count - 1 do
            TPCOperationsComp(BlocksList[i]).Free;
          BlocksList.Free;
        end;
        start := Bank.BlocksCount;
      until (Bank.BlocksCount = Connection.FRemoteOperationBlock.block + 1) or (finished);
      // New Build 1.5 more work vs more high
      // work = SUM(target) of all previous blocks (Int64)
      // -----------------------------
      // Before of version 1.5 was: "if Bank.BlocksCount > TNode.Node.Bank.BlocksCount then ..."
      // Starting on version 1.5 is: "if Bank.WORK > MyBank.WORK then ..."
      if Bank.SafeBox.WorkSum > TNode.Node.Bank.SafeBox.WorkSum then
      begin
        TNode.Node.DisableNewBlocks;
        try
          // I'm an orphan blockchain...
          TLog.NewLog(ltinfo, CT_LogSender, 'New valid blockchain found. My block count = ' + inttostr(TNode.Node.Bank.BlocksCount) + ' work: ' + IntToStr(TNode.Node.Bank.SafeBox.WorkSum)+
            ' found count = ' + inttostr(Bank.BlocksCount) + ' work: ' + IntToStr(Bank.SafeBox.WorkSum) + ' starting at block ' + inttostr(start_block));
          TNode.Node.Bank.Storage.MoveBlockChainBlocks(start_block, Inttostr(start_block) + '_' + FormatDateTime('yyyymmddhhnnss', DateTime2UnivDateTime(now)), Nil);
          Bank.Storage.MoveBlockChainBlocks(start_block, TNode.Node.Bank.Storage.Orphan, TNode.Node.Bank.Storage);
          TNode.Node.Bank.DiskRestoreFromOperations(CT_MaxBlock);
        finally
          TNode.Node.EnableNewBlocks;
        end;
      end
      else
      begin
        if (not IsAScam) and (Connection.FRemoteAccumulatedWork > TNode.Node.Bank.SafeBox.WorkSum) then
        begin
          // Possible scammer!
          Connection.DisconnectInvalidClient(false, Format('Possible scammer! Says blocks:%d Work:% - Obtained blocks:%d work:%d',
            [Connection.FRemoteOperationBlock.block + 1, Connection.FRemoteAccumulatedWork,
             Bank.BlocksCount, Bank.SafeBox.WorkSum]));
        end;
      end;
    finally
      Bank.Free;
    end;
  end;

var
  rid : Cardinal;
  my_op, client_op : TOperationBlock;
begin
  // Protection against discovering servers...
  if FIsDiscoveringServers then
  begin
    TLog.NewLog(ltdebug, CT_LogSender, 'Is discovering servers...');
    exit;
  end;
  //
  if FIsGettingNewBlockChainFromClient then
  begin
    TLog.NewLog(ltdebug, CT_LogSender, 'Is getting new blockchain from client...');
    exit;
  end
  else
    TLog.NewLog(ltdebug, CT_LogSender, 'Starting receiving: ' + why);
  try
    FIsGettingNewBlockChainFromClient := true;
    FMaxRemoteOperationBlock := Connection.FRemoteOperationBlock;
    if TNode.Node.Bank.BlocksCount = 0 then
    begin
      TLog.NewLog(ltdebug, CT_LogSender, 'I have no blocks');
      Connection.Send_GetBlocks(0, 10, rid);
      exit;
    end;
    TLog.NewLog(ltdebug, CT_LogSender, 'Starting GetNewBlockChainFromClient at client:' + Connection.ClientRemoteAddr+
      ' with OperationBlock:' + TPCOperationsComp.OperationBlockToText(Connection.FRemoteOperationBlock) + ' (My block: ' + TPCOperationsComp.OperationBlockToText(TNode.Node.Bank.LastOperationBlock) + ')');
    // NOTE: FRemoteOperationBlock.block >= TNode.Node.Bank.BlocksCount
    // First capture same block than me (TNode.Node.Bank.BlocksCount-1) to check if i'm an orphan block...
    my_op := TNode.Node.Bank.LastOperationBlock;
    if not Do_GetOperationBlock(my_op.block, 5000, client_op) then
    begin
      TLog.NewLog(lterror, CT_LogSender, 'Cannot receive information about my block (' + inttostr(my_op.block) + ')...');
      // Disabled at Build 1.0.6 >  Connection.DisconnectInvalidClient(false, 'Cannot receive information about my block (' + inttostr(my_op.block) + ')... Invalid client. Disconnecting');
      exit;
    end;

    if (not TPCOperationsComp.EqualsOperationBlock(my_op, client_op)) then
    begin
      TLog.NewLog(ltinfo, CT_LogSender, 'My blockchain is not equal... received: ' + TPCOperationsComp.OperationBlockToText(client_op) + ' My: ' + TPCOperationsComp.OperationBlockToText(my_op));
      if not FindLastSameBlockByOperationsBlock(0, client_op.block, client_op) then
      begin
        TLog.NewLog(ltinfo, CT_LogSender, 'No found base block to start process... Receiving ALL');
        GetNewBank(-1);
      end else
      begin
        TLog.NewLog(ltinfo, CT_LogSender, 'Found base new block: ' + TPCOperationsComp.OperationBlockToText(client_op));
        // Move operations to orphan folder... (temporal... waiting for a confirmation)
        GetNewBank(client_op.block);
      end;
    end else
    begin
      TLog.NewLog(ltinfo, CT_LogSender, 'My blockchain is ok! Need to download new blocks starting at ' + inttostr(my_op.block + 1));
      // High to new value:
      Connection.Send_GetBlocks(my_op.block + 1, 100, rid);
    end;
  finally
    TLog.NewLog(ltdebug, CT_LogSender, 'Finalizing');
    FIsGettingNewBlockChainFromClient := false;
  end;
end;

function TNetData.GetValidNodeServers(OnlyWhereIConnected : Boolean; Max : Integer): TNodeServerAddressArray;
var i, j : Integer;
  nsa : TNodeServerAddress;
  currunixtimestamp : Cardinal;
  l : TList;
  Aux : TNodeServerAddressArray;
begin
  SetLength(Result, 0);
  SetLength(Aux, 0);
  currunixtimestamp := UnivDateTimeToUnix(DateTime2UnivDateTime(now));
  // Save other node servers
  l := FNodeServersAddresses.LockList;
  try
    for i := 0 to l.Count - 1 do
    begin
      nsa := PNodeServerAddress( l[i] )^;
      if (not IsBlackListed(nsa.ip, 0))
        and
        ( // I've connected 24h before
         ((nsa.last_connection > 0) and ((Assigned(nsa.netConnection)) or ((nsa.last_connection + (60*60*24)) > (currunixtimestamp))))
         or // Others have connected 24h before
         ((nsa.last_connection_by_server > 0) and ((nsa.last_connection_by_server + (60*60*24)) > (currunixtimestamp)))
         or // Peer cache
         ((nsa.last_connection = 0) and (nsa.last_connection_by_server = 0))
        )
        and
        ( // Never tried to connect or successfully connected
          (nsa.total_failed_attemps_to_connect = 0)
        )
        and
        (
          (not OnlyWhereIConnected)
          or
          (nsa.last_connection > 0)
        )
        then
      begin
        SetLength(Aux, length(Aux) + 1);
        Aux[high(Aux)] := nsa;
      end;
    end;
  finally
    FNodeServersAddresses.UnlockList;
  end;
  if (Max <= 0) or (length(Aux) < Max) then
  begin
    Result := Aux;
  end else
  begin
    for i := 1 to Max do
    begin
      j := Random(length(Aux));
      if Aux[j].ip <> '' then
      begin
        SetLength(Result, length(Result) + 1);
        Result[high(Result)] := Aux[j];
        Aux[j].ip := '';
      end;
    end;
  end;
end;

class function TNetData.HeaderDataToText(const HeaderData: TNetHeaderData): AnsiString;
begin
  Result := CT_NetTransferType[HeaderData.header_type] + ' Operation:' + TNetData.OperationToText(HeaderData.operation);
  if HeaderData.is_error then
  begin
    Result := Result +' ERRCODE:' + Inttostr(HeaderData.error_code) + ' ERROR:' + HeaderData.error_text;
  end else
  begin
    Result := Result +' ReqId:' + Inttostr(HeaderData.request_id) + ' BufferSize:' + Inttostr(HeaderData.buffer_data_length);
  end;
end;

procedure TNetData.IncStatistics(incActiveConnections, incClientsConnections,
  incServersConnections, incServersConnectionsWithResponse: Integer; incBytesReceived, incBytesSend: Int64);
begin
  // Multithread prevention
  FNodeServersAddresses.LockList;
  try
    FNetStatistics.ActiveConnections := FNetStatistics.ActiveConnections + incActiveConnections;
    FNetStatistics.ClientsConnections := FNetStatistics.ClientsConnections + incClientsConnections;
    FNetStatistics.ServersConnections := FNetStatistics.ServersConnections + incServersConnections;
    FNetStatistics.ServersConnectionsWithResponse := FNetStatistics.ServersConnectionsWithResponse + incServersConnectionsWithResponse;
    if (incActiveConnections > 0) then
      FNetStatistics.TotalConnections := FNetStatistics.TotalConnections + incActiveConnections;
    if (incClientsConnections > 0) then
      FNetStatistics.TotalClientsConnections := FNetStatistics.TotalClientsConnections + incClientsConnections;
    if (incServersConnections > 0) then
      FNetStatistics.TotalServersConnections := FNetStatistics.TotalServersConnections + incServersConnections;
    FNetStatistics.BytesReceived := FNetStatistics.BytesReceived + incBytesReceived;
    FNetStatistics.BytesSend := FNetStatistics.BytesSend + incBytesSend;
  finally
    FNodeServersAddresses.UnlockList;
  end;
  NotifyStatisticsChanged;
  if (incBytesReceived <> 0) or (incBytesSend <> 0) then
  begin
    NotifyNetConnectionUpdated;
  end;
end;

function TNetData.IndexOfNetClient(ListToSearch: TList; ip: AnsiString; port: Word; indexStart : Integer = 0): Integer;
var P : PNodeServerAddress;
begin
  if indexStart < 0 then indexStart := 0;
  for Result := indexStart to ListToSearch.Count - 1 do
  begin
    P := ListToSearch[Result];
    if (AnsiSameText( P^.ip, ip)) and ((port = 0) or (P^.port = port)) then
      exit;
  end;
  Result := -1;
end;

function TNetData.IsBlackListed(const ip: AnsiString; port: Word): Boolean;
var
  l : TList;
  i : Integer;
begin
  Result := false;
  l := FNodeServersAddresses.LockList;
  try
    i := -1;
    repeat
      i := IndexOfNetClient(l, ip, port, i + 1);
      if (i >= 0) then
      begin
        if (PNodeServerAddress(l[i])^.is_blacklisted) then
        begin
          Result := not PNodeServerAddress(l[i])^.its_myself;
        end;
      end;
    until (i < 0) or (Result);
  finally
    FNodeServersAddresses.UnlockList;
  end;
end;

class function TNetData.NetData: TNetData;
begin
  if not Assigned(_NetData) then
  begin
    _NetData := TNetData.Create(nil);
  end;
  result := _NetData;
end;

class function TNetData.NetDataExists: Boolean;
begin
  Result := Assigned(_NetData);
end;

function TNetData.NewRequestId: Cardinal;
begin
  Inc(FLastRequestId);
  Result := FLastRequestId;
end;

procedure TNetData.Notification(AComponent: TComponent; Operation: TOperation);
var l : TList;
begin
  inherited;
  if Operation = OpRemove then
  begin
    if not (csDestroying in ComponentState) then
    begin
      l := FNetConnections.LockList;
      try
        if l.Remove(AComponent) >= 0 then
        begin
          NotifyNetConnectionUpdated;
        end;
      finally
        FNetConnections.UnlockList;
      end;
    end;
  end;
end;

procedure TNetData.NotifyBlackListUpdated;
begin
  FNetDataNotifyEventsThread.FNotifyOnBlackListUpdated := true;
end;

procedure TNetData.NotifyNetConnectionUpdated;
begin
  FNetDataNotifyEventsThread.FNotifyOnNetConnectionsUpdated := true;
end;

procedure TNetData.NotifyNodeServersUpdated;
begin
  FNetDataNotifyEventsThread.FNotifyOnNodeServersUpdated := true;
end;

procedure TNetData.NotifyReceivedHelloMessage;
begin
  FNetDataNotifyEventsThread.FNotifyOnReceivedHelloMessage := true;
end;

procedure TNetData.NotifyStatisticsChanged;
begin
  FNetDataNotifyEventsThread.FNotifyOnStatisticsChanged := true;
end;

class function TNetData.OperationToText(operation: Word): AnsiString;
begin
  case operation of
    CT_NetOp_Hello              : Result := 'HELLO';
    CT_NetOp_Error              : Result := 'ERROR';
    CT_NetOp_GetBlocks          : Result := 'GET BLOCKS';
    CT_NetOp_Message            : Result := 'MESSAGE';
    CT_NetOp_GetOperationsBlock : Result := 'GET OPERATIONS BLOCK';
    CT_NetOp_NewBlock           : Result := 'NEW BLOCK';
    CT_NetOp_AddOperations      : Result := 'ADD OPERATIONS';
  else
    Result := 'UNKNOWN OPERATION ' + Inttohex(operation, 4);
  end;
end;

function TNetData.PendingRequest(Sender: TNetConnection; var requests_data : AnsiString): Integer;
var
  i : Integer;
  l : TList;
begin
  requests_data := '';
  l := FRegisteredRequests.LockList;
  try
    if Assigned(Sender) then
    begin
      Result := 0;
      for i := l.Count - 1 downto 0 do
      begin
        if (PNetRequestRegistered(l[i])^.NetClient = Sender) then
        begin
          requests_data := requests_data + 'Op:' + OperationToText(PNetRequestRegistered(l[i])^.Operation) + ' Id:' + Inttostr(PNetRequestRegistered(l[i])^.RequestId) + ' - ';
          inc(Result);
        end;
      end;
    end
    else
      Result := l.Count;
  finally
    FRegisteredRequests.UnlockList;
  end;
end;

procedure TNetData.RegisterRequest(Sender: TNetConnection; operation: Word; request_id: Cardinal);
var P : PNetRequestRegistered;
  l : TList;
begin
  l := FRegisteredRequests.LockList;
  try
    New(P);
    P^.NetClient := Sender;
    P^.Operation := operation;
    P^.RequestId := request_id;
    P^.SendTime := Now;
    l.Add(P);
    TLog.NewLog(ltdebug, Classname, 'Registering request to ' + Sender.ClientRemoteAddr + ' Op:' + OperationToText(operation) + ' Id:' + inttostr(request_id) + ' Total pending:' + Inttostr(l.Count));
  finally
    FRegisteredRequests.UnlockList;
  end;
end;

procedure TNetData.SetNetConnectionsActive(const Value: Boolean);
begin
  FNetConnectionsActive := Value;
  if FNetConnectionsActive then
    DiscoverServers
  else
    DisconnectClients;
end;

function TNetData.UnRegisterRequest(Sender: TNetConnection; operation: Word; request_id: Cardinal): Boolean;
var P : PNetRequestRegistered;
  i : Integer;
  l : TList;
begin
  Result := false;
  l := FRegisteredRequests.LockList;
  try
    for i := l.Count - 1 downto 0 do
    begin
      P := l[i];
      if (P^.NetClient = Sender) and
        ( ((Operation = P^.Operation) and (request_id = P^.RequestId))
          Or
          ((operation = 0) and (request_id = 0)) ) then
      begin
        l.Delete(i);
        Dispose(P);
        Result := true;
        if Assigned(Sender.FTcpIpClient) then
        begin
          TLog.NewLog(ltdebug, Classname, 'Unregistering request to ' + Sender.ClientRemoteAddr + ' Op:' + OperationToText(operation) + ' Id:' + inttostr(request_id) + ' Total pending:' + Inttostr(l.Count));
        end else
        begin
          TLog.NewLog(ltdebug, Classname, 'Unregistering request to (NIL) Op:' + OperationToText(operation) + ' Id:' + inttostr(request_id) + ' Total pending:' + Inttostr(l.Count));
        end;
      end;
    end;
  finally
    FRegisteredRequests.UnlockList;
  end;
end;

{ TNetServer }

constructor TNetServer.Create;
begin
  inherited;
  MaxConnections := CT_MaxClientsConnected;
  NetTcpIpClientClass := TBufferedNetTcpIpClient;
  Port := CT_NetServer_Port;
end;

procedure TNetServer.OnNewIncommingConnection(Sender : TObject; Client : TNetTcpIpClient);
var n : TNetServerClient;
  DebugStep : String;
begin
  DebugStep := '';
  try
    if not Client.Connected then
      exit;
    // NOTE: I'm in a separate thread
    // While in this function the ClientSocket connection will be active, when finishes the ClientSocket will be destroyed
    TLog.NewLog(ltInfo, Classname, 'Starting ClientSocket accept ' + Client.ClientRemoteAddr);
    n := TNetServerClient.Create(nil);
    try
      DebugStep := 'Assigning client';
      n.SetClient(Client);
      TNetData.NetData.IncStatistics(1, 1, 0, 0, 0, 0);
      TNetData.NetData.CleanBlackList;
      DebugStep := 'Checking blacklisted';
      if (TNetData.NetData.IsBlackListed(Client.RemoteHost, 0)) then
      begin
        // Invalid!
        TLog.NewLog(ltinfo, Classname, 'Refusing Blacklist ip: ' + Client.ClientRemoteAddr);
        n.SendError(ntp_autosend, CT_NetOp_Error, 0, CT_NetError_IPBlackListed, 'Your IP is blacklisted:' + Client.ClientRemoteAddr);
        // Wait some time before close connection
        Sleep(5000);
      end else
      begin
        DebugStep := 'Processing buffer and sleep...';
        while (n.Connected) and (Active) do
        begin
          n.DoProcessBuffer;
          Sleep(10);
        end;
      end;
    finally
      try
        TLog.NewLog(ltdebug, Classname, 'Finalizing ServerAccept ' + IntToHex(PtrInt(n), 8) + ' ' + n.ClientRemoteAddr);
        DebugStep := 'Disconnecting NetServerClient';
        n.Connected := false;
        sleep(10);
        DebugStep := 'Assigning old client';
        n.SetClient( NetTcpIpClientClass.Create(Nil) );
      finally
        DebugStep := 'Freeing NetServerClient';
        n.Free;
      end;
    end;
  except
    on E:Exception do begin
      TLog.NewLog(lterror, ClassName, 'Exception processing client thread at step: ' + DebugStep + ' - (' + E.ClassName + ') ' + E.Message);
    end;
  end;
end;

procedure TNetServer.SetActive(const Value: Boolean);
begin
  if Value then
  begin
    TLog.NewLog(ltinfo, Classname, 'Activating server on port ' + IntToStr(Port));
  end else
  begin
    TLog.NewLog(ltinfo, Classname, 'Closing server');
  end;
  inherited;
  if Active then
  begin
    // TNode.Node.AutoDiscoverNodes(CT_Discover_IPs);
  end else
  if TNetData.NetDataExists then
  begin
    TNetData.NetData.DisconnectClients;
  end;
end;

{ TNetConnection }

function TNetConnection.ClientRemoteAddr: AnsiString;
begin
  if Assigned(FTcpIpClient) then
  begin
    Result := FtcpIpClient.ClientRemoteAddr
  end
  else
    Result := 'NIL';
end;

function TNetConnection.ConnectTo(ServerIP: String; ServerPort: Word) : Boolean;
var
  Pnsa : PNodeServerAddress;
  lns : TList;
  i : Integer;
begin
  if Client.Connected then Client.Disconnect;
  lns := TNetData.NetData.NodeServersAddresses.LockList;
  try
    i := TNetData.NetData.IndexOfNetClient(lns, ServerIp, ServerPort);
    if (i >= 0) then
      Pnsa := lns[i]
    else
      Pnsa := nil;
    if Assigned(Pnsa) then
      Pnsa^.netConnection := Self;
  finally
    TNetData.NetData.NodeServersAddresses.UnlockList;
  end;

  TPCThread.ProtectEnterCriticalSection(Self, FNetLock);
  try
    Client.RemoteHost := ServerIP;
    if ServerPort <= 0 then
      ServerPort := CT_NetServer_Port;
    Client.RemotePort := ServerPort;
    TLog.NewLog(ltDebug, Classname, 'Trying to connect to a server at: ' + ClientRemoteAddr);
    TNetData.NetData.NotifyNetConnectionUpdated;
    Result := Client.Connect;
  finally
    FNetLock.Release;
  end;
  if Result then
  begin
    TLog.NewLog(ltDebug, Classname, 'Connected to a possible server at: ' + ClientRemoteAddr);
    Result := Send_Hello(ntp_request, TNetData.NetData.NewRequestId);
  end
  else
  begin
    TLog.NewLog(ltDebug, Classname, 'Cannot connect to a server at: ' + ClientRemoteAddr);
  end;
end;

constructor TNetConnection.Create(AOwner: TComponent);
begin
  inherited;
  FIsDownloadingBlocks := false;
  FHasReceivedData := false;
  FNetProtocolVersion.protocol_version := 0; // 0 = unknown
  FNetProtocolVersion.protocol_available := 0;
  FAlertedForNewProtocolAvailable := false;
  FDoFinalizeConnection := false;
  FClientAppVersion := '';
  FClientPublicKey := CT_TECDSA_Public_Nul;
  FCreatedTime := Now;
  FIsMyselfServer := false;
  FLastKnownTimestampDiff := 0;
  FIsWaitingForResponse := false;
  FClientBufferRead := TMemoryStream.Create;
  FNetLock := TPCCriticalSection.Create('TNetConnection_NetLock');
  FLastDataReceivedTS := 0;
  FLastDataSendedTS := 0;
  FRandomWaitSecondsSendHello := 90 + Random(60);
  FTcpIpClient := nil;
  FRemoteOperationBlock := CT_OperationBlock_NUL;
  FRemoteAccumulatedWork := 0;
  SetClient( TBufferedNetTcpIpClient.Create(Self) );
  TNetData.NetData.FNetConnections.Add(Self);
  TNetData.NetData.NotifyNetConnectionUpdated;
end;

destructor TNetConnection.Destroy;
var Pnsa : PNodeServerAddress;
  lns : TList;
  i : Integer;
begin
  TLog.NewLog(ltdebug, ClassName, 'Destroying ' + Classname + ' ' + IntToHex(PtrInt(Self), 8));

  Connected := false;

  lns := TNetData.NetData.NodeServersAddresses.LockList;
  try
    for i := lns.Count - 1 downto 0 do
    begin
      Pnsa := lns[i];
      if Pnsa^.netConnection = Self then
      begin
        Pnsa^.netConnection := nil;
      end;
    end;
  finally
    TNetData.NetData.NodeServersAddresses.UnlockList;
  end;
  TNetData.NetData.FNetConnections.Remove(Self);
  TNetData.NetData.UnRegisterRequest(Self, 0, 0);
  try
    TNetData.NetData.NotifyNetConnectionUpdated;
  finally
    FreeAndNil(FNetLock);
    FreeAndNil(FClientBufferRead);
    FreeAndNil(FTcpIpClient);
    inherited;
  end;
end;

procedure TNetConnection.DisconnectInvalidClient(ItsMyself : Boolean; const why: AnsiString);
var P : PNodeServerAddress;
  l : TList;
  i : Integer;
  include_in_list : Boolean;
begin
  FIsDownloadingBlocks := false;
  if ItsMyself then
  begin
    TLog.NewLog(ltInfo, Classname, 'Disconecting myself ' + ClientRemoteAddr + ' > ' + Why)
  end else
  begin
    TLog.NewLog(lterror, Classname, 'Disconecting ' + ClientRemoteAddr + ' > ' + Why);
  end;
  FIsMyselfServer := ItsMyself;
  include_in_list := (not SameText(Client.RemoteHost, 'localhost')) and (not SameText(Client.RemoteHost, '127.0.0.1'))
    and (not SameText('192.168.', Copy(Client.RemoteHost, 1, 8)))
    and (not SameText('10.', Copy(Client.RemoteHost, 1, 3)));
  if include_in_list then
  begin
    l := TNetData.NetData.NodeServersAddresses.LockList;
    try
      i := TNetData.NetData.IndexOfNetClient(l, Client.RemoteHost, Client.RemotePort);
      if i < 0 then
      begin
        new(P);
        P^ := CT_TNodeServerAddress_NUL;
        l.Add(P);
      end
      else
        P := l[i];
      P^.ip := Client.RemoteHost;
      P^.port := Client.RemotePort;
      P^.last_connection := UnivDateTimeToUnix(DateTime2UnivDateTime(now));
      P^.its_myself := ItsMyself;
      P^.BlackListText := Why;
      P^.is_blacklisted := true;
    finally
      TNetData.NetData.NodeServersAddresses.UnlockList;
    end;
  end
  else
  if ItsMyself then
  begin
    l := TNetData.NetData.NodeServersAddresses.LockList;
    try
      i := TNetData.NetData.IndexOfNetClient(l, Client.RemoteHost, Client.RemotePort);
      if i >= 0 then
      begin
        P := l[i];
        P^.its_myself := ItsMyself;
      end;
    finally
      TNetData.NetData.NodeServersAddresses.UnlockList;
    end;
  end;
  Connected := False;
  TNetData.NetData.NotifyBlackListUpdated;
  TNetData.NetData.NotifyNodeServersUpdated;
end;

Procedure TNetConnection.DoProcessBuffer;
var
  HeaderData : TNetHeaderData;
  ms : TMemoryStream;
  ops : AnsiString;
begin
  if FDoFinalizeConnection then
  begin
    TLog.NewLog(ltdebug, Classname, 'Executing DoFinalizeConnection at client ' + ClientRemoteAddr);
    Connected := false;
  end;
  if not Connected then
    exit;
  ms := TMemoryStream.Create;
  try
    if not FIsWaitingForResponse then
    begin
      DoSendAndWaitForResponse(0, 0, Nil, ms, 0, HeaderData);
    end;
  finally
    ms.Free;
  end;
  if ((FLastDataReceivedTS > 0) or ( not (self is TNetServerClient)))
     and ((FLastDataReceivedTS + (1000*FRandomWaitSecondsSendHello) < GetTickCount) and (FLastDataSendedTS + (1000*FRandomWaitSecondsSendHello) < GetTickCount)) then
  begin
    // Build 1.4 -> Changing wait time from 120 secs to a random seconds value
    if TNetData.NetData.PendingRequest(Self, ops) >= 2 then
    begin
      TLog.NewLog(ltDebug, Classname, 'Pending requests without response... closing connection to ' + ClientRemoteAddr + ' > ' + ops);
      Connected := false;
    end else
    begin
      TLog.NewLog(ltDebug, Classname, 'Sending Hello to check connection to ' + ClientRemoteAddr + ' > ' + ops);
      Send_Hello(ntp_request, TNetData.NetData.NewRequestId);
    end;
  end else
  if (Self is TNetServerClient) and (FLastDataReceivedTS = 0) and (FCreatedTime + EncodeTime(0, 1, 0, 0) < Now) then
  begin
    // Disconnecting client without data...
    TLog.NewLog(ltDebug, Classname, 'Disconnecting client without data ' + ClientRemoteAddr);
    Connected := false;
  end;
end;

procedure TNetConnection.DoProcess_AddOperations(HeaderData: TNetHeaderData; DataBuffer: TStream);
var c, i : Integer;
    optype : Byte;
    opclass : TPCOperationClass;
    op : TPCOperation;
    operations : TOperationsHashTree;
    errors : AnsiString;
  DoDisconnect : Boolean;
begin
  DoDisconnect := true;
  operations := TOperationsHashTree.Create;
  try
    if HeaderData.header_type <> ntp_autosend then
    begin
      errors := 'Not autosend';
      exit;
    end;
    if DataBuffer.Size < 4 then
    begin
      errors := 'Invalid databuffer size';
      exit;
    end;
    DataBuffer.Read(c, 4);
    for i := 1 to c do
    begin
      errors := 'Invalid operation ' + inttostr(i) + '/' + inttostr(c);
      if not DataBuffer.Read(optype, 1) = 1 then
        exit;
      opclass := TPCOperationsComp.GetOperationClassByOpType(optype);
      if not Assigned(opclass) then
        exit;
      op := opclass.Create;
      try
        op.LoadFromStream(DataBuffer);
        operations.AddOperationToHashTree(op);
      finally
        op.Free;
      end;
    end;
    DoDisconnect := false;
  finally
    try
      if DoDisconnect then
      begin
        DisconnectInvalidClient(false, errors + ' > ' + TNetData.HeaderDataToText(HeaderData) + ' BuffSize: ' + inttostr(DataBuffer.Size));
      end else
      begin
        TNode.Node.AddOperations(Self, operations, Nil, errors);
      end;
    finally
      operations.Free;
    end;
  end;
end;

procedure TNetConnection.DoProcess_GetBlocks_Request(HeaderData: TNetHeaderData; DataBuffer: TStream);
var
  b, b_start, b_end:Cardinal;
  op : TPCOperationsComp;
  db : TMemoryStream;
  c : Cardinal;
  errors : AnsiString;
  DoDisconnect : Boolean;
  posquantity : Int64;
begin
  DoDisconnect := true;
  try
    if HeaderData.header_type <> ntp_request then
    begin
      errors := 'Not request';
      exit;
    end;
    // DataBuffer contains: from and to
    errors := 'Invalid structure';
    if (DataBuffer.Size-DataBuffer.Position < 8) then
    begin
      exit;
    end;
    DataBuffer.Read(b_start, 4);
    DataBuffer.Read(b_end, 4);
    if (b_start < 0) or (b_start > b_end) then
    begin
      errors := 'Invalid structure start or end: ' + Inttostr(b_start) + ' ' + Inttostr(b_end);
      exit;
    end;
    if (b_end >= TNetData.NetData.Bank.BlocksCount) then
      b_end := TNetData.NetData.Bank.BlocksCount-1;

     DoDisconnect := false;

     db := TMemoryStream.Create;
     try
       op := TPCOperationsComp.Create(TNetData.NetData.bank);
       try
         c := b_end - b_start + 1;
         posquantity := db.position;
         db.Write(c, 4);
         c := 0;
         b := b_start;
         for b := b_start to b_end do
         begin
           inc(c);
           if TNetData.NetData.bank.LoadOperations(op, b) then
           begin
             op.SaveBlockToStream(false, db);
           end
           else
           begin
             SendError(ntp_response, HeaderData.operation, HeaderData.request_id, CT_NetError_InternalServerError, 'Operations of block:' + inttostr(b) + ' not found');
             exit;
           end;
           // Build 1.0.5 To prevent high data over net in response (Max 2 Mb of data)
           if (db.size > (1024*1024*2)) then
           begin
             // Stop
             db.position := posquantity;
             db.Write(c, 4);
             // BUG of Build 1.0.5 !!! Need to break bucle OH MY GOD!
             db.Position := db.Size;
             break;
           end;
         end;
         Send(ntp_response, HeaderData.operation, 0, HeaderData.request_id, db);
       finally
         op.Free;
       end;
     finally
       db.Free;
     end;
     TLog.NewLog(ltdebug, Classname, 'Sending operations from block ' + inttostr(b_start) + ' to ' + inttostr(b_end));
  finally
    if DoDisconnect then
    begin
      DisconnectInvalidClient(false, errors + ' > ' + TNetData.HeaderDataToText(HeaderData) + ' BuffSize: ' + inttostr(DataBuffer.Size));
    end;
  end;
end;

procedure TNetConnection.DoProcess_GetBlocks_Response(HeaderData: TNetHeaderData; DataBuffer: TStream);
var
  op, localop : TPCOperationsComp;
  opcount, i : Cardinal;
  newBlockAccount : TBlockAccount;
  errors : AnsiString;
  DoDisconnect : Boolean;
begin
  DoDisconnect := true;
  try
    if HeaderData.header_type <> ntp_response then begin
      errors := 'Not response';
      exit;
    end;
    // DataBuffer contains: from and to
    errors := 'Invalid structure';
    op := TPCOperationsComp.Create(nil);
    try
      op.bank := TNode.Node.Bank;
      if DataBuffer.Size-DataBuffer.Position < 4 then begin
        DisconnectInvalidClient(false, 'DoProcess_GetBlocks_Response invalid format: ' + errors);
        exit;
      end;
      DataBuffer.Read(opcount, 4);
      DoDisconnect :=false;
      for I := 1 to opcount do
      begin
        if not op.LoadBlockFromStream(DataBuffer, errors) then
        begin
           errors := 'Error decoding block ' + inttostr(i) + '/' + inttostr(opcount) + ' Errors:' + errors;
           DoDisconnect := true;
           exit;
        end;
        if (op.OperationBlock.block = TNode.Node.Bank.BlocksCount) then
        begin
          if (TNode.Node.Bank.AddNewBlockChainBlock(op, newBlockAccount, errors)) then
          begin
            // Ok, one more!
          end
          else
          begin
            // Is not a valid entry????
            // Perhaps an orphan blockchain: Me or Client!
            localop := TPCOperationsComp.Create(nil);
            try
              TNode.Node.Bank.LoadOperations(localop, TNode.Node.Bank.BlocksCount-1);
              TLog.NewLog(ltinfo, Classname, 'Distinct operation block found! My:'+
                  TPCOperationsComp.OperationBlockToText(localop.OperationBlock) + ' remote:' + TPCOperationsComp.OperationBlockToText(op.OperationBlock) + ' Errors: ' + errors);
            finally
              localop.Free;
            end;
          end;
        end
        else
        begin
          // Receiving an unexpected operationblock
          TLog.NewLog(lterror, classname, 'Received a distinct block, finalizing: ' + TPCOperationsComp.OperationBlockToText(op.OperationBlock) + ' (My block: ' + TPCOperationsComp.OperationBlockToText(TNode.Node.Bank.LastOperationBlock) + ')' );
          FIsDownloadingBlocks := false;
          exit;
        end;
      end;
      FIsDownloadingBlocks := false;
      if ((opcount > 0) and (FRemoteOperationBlock.block >= TNode.Node.Bank.BlocksCount)) then
      begin
        Send_GetBlocks(TNode.Node.Bank.BlocksCount, 100, i);
      end;
      TNode.Node.NotifyBlocksChanged;
    finally
      op.Free;
    end;
  finally
    if DoDisconnect then
    begin
      DisconnectInvalidClient(false, errors + ' > ' + TNetData.HeaderDataToText(HeaderData) + ' BuffSize: ' + inttostr(DataBuffer.Size));
    end;
  end;
end;

procedure TNetConnection.DoProcess_GetOperationsBlock_Request(HeaderData: TNetHeaderData; DataBuffer: TStream);
const
  CT_Max_Positions = 10;
var
  inc_b, b, b_start, b_end, total_b:Cardinal;
  op : TPCOperationsComp;
  db, msops : TMemoryStream;
  errors, blocksstr : AnsiString;
  DoDisconnect : Boolean;
begin
  blocksstr := '';
  DoDisconnect := true;
  try
    if HeaderData.header_type <> ntp_request then
    begin
      errors := 'Not request';
      exit;
    end;
    errors := 'Invalid structure';
    if (DataBuffer.Size-DataBuffer.Position < 8) then
    begin
      exit;
    end;
    DataBuffer.Read(b_start, 4);
    DataBuffer.Read(b_end, 4);
    if (b_start < 0) or (b_start > b_end) or (b_start >= TNode.Node.Bank.BlocksCount) then
    begin
      errors := 'Invalid start (' + Inttostr(b_start) + ') or end (' + Inttostr(b_end) + ') of count (' + Inttostr(TNode.Node.Bank.BlocksCount) + ')';
      exit;
    end;

    DoDisconnect := false;

    // Build 1.4
    if b_start < TNode.Node.Bank.Storage.FirstBlock then
    begin
      b_start := TNode.Node.Bank.Storage.FirstBlock;
      if b_end < b_start then
      begin
        errors := 'Block:' + inttostr(b_end) + ' not found';
        SendError(ntp_response, HeaderData.operation, HeaderData.request_id, CT_NetError_InternalServerError, errors);
        exit;
      end;
    end;

    if (b_end >= TNode.Node.Bank.BlocksCount) then
      b_end := TNode.Node.Bank.BlocksCount-1;
    inc_b := ((b_end - b_start) div CT_Max_Positions) + 1;
    msops := TMemoryStream.Create;
    op := TPCOperationsComp.Create(TNode.Node.Bank);
     try
       b := b_start;
       total_b := 0;
       repeat
         if TNode.Node.bank.LoadOperations(op, b) then
         begin
           op.SaveBlockToStream(true, msops);
           blocksstr := blocksstr + inttostr(b) + ',';
           b := b + inc_b;
           inc(total_b);
         end else
         begin
           errors := 'Operations of block:' + inttostr(b) + ' not found';
           SendError(ntp_response, HeaderData.operation, HeaderData.request_id, CT_NetError_InternalServerError, errors);
           exit;
         end;
       until (b > b_end);
       db := TMemoryStream.Create;
       try
         db.Write(total_b, 4);
         db.WriteBuffer(msops.Memory^, msops.Size);
         Send(ntp_response, HeaderData.operation, 0, HeaderData.request_id, db);
       finally
         db.Free;
       end;
     finally
       msops.Free;
       op.Free;
     end;
     TLog.NewLog(ltdebug, Classname, 'Sending ' + inttostr(total_b) + ' operations block from block ' + inttostr(b_start) + ' to ' + inttostr(b_end) + ' ' + blocksstr);
  finally
    if DoDisconnect then
    begin
      DisconnectInvalidClient(false, errors + ' > ' + TNetData.HeaderDataToText(HeaderData) + ' BuffSize: ' + inttostr(DataBuffer.Size));
    end;
  end;
end;

procedure TNetConnection.DoProcess_Hello(HeaderData: TNetHeaderData; DataBuffer: TStream);
(*
  function IsValidTime(connection_ts : Cardinal) : Boolean;
  var
    l : TList;
    i : Integer;
    nc : TNetConnection;
    min_valid_time, max_valid_time : Cardinal;
    showmessage : Boolean;
  Begin
    if ((FLastKnownTimestampDiff < ((-1)*(CT_MaxSecondsDifferenceOfNetworkNodes div 2)))
        or (FLastKnownTimestampDiff > (CT_MaxSecondsDifferenceOfNetworkNodes div 2))) then
    begin
      TLog.NewLog(ltdebug, Classname, 'Processing a hello from a client with different time. Difference: ' + Inttostr(FLastKnownTimestampDiff));
    end;
    min_valid_time := (UnivDateTimeToUnix(DateTime2UnivDateTime(now))-CT_MaxSecondsDifferenceOfNetworkNodes);
    max_valid_time := (UnivDateTimeToUnix(DateTime2UnivDateTime(now)) + CT_MaxSecondsDifferenceOfNetworkNodes);
    if (connection_ts < min_valid_time) or (connection_ts > max_valid_time) then
    begin
      Result := false;
      showmessage := true;
      // This message only appears if there is no other valid connections
      if TNetData.NetData.NetConnections.TryLockList(5000, l) then
      begin
        try
          for i := 0 to l.Count - 1 do
          begin
            nc :=(TNetConnection(l[i]));
            if (nc <> self) and (nc.FHasReceivedData) and (nc.Connected)
              and (nc.FLastKnownTimestampDiff >= ((-1)*CT_MaxSecondsDifferenceOfNetworkNodes))
              and (nc.FLastKnownTimestampDiff <= (CT_MaxSecondsDifferenceOfNetworkNodes))
              then
            begin
              showmessage := false;
              break;
            end;
          end;
        finally
          TNetData.NetData.NetConnections.UnlockList;
        end;
        if showmessage then
        begin
          TNode.Node.NotifyNetClientMessage(nil, 'Detected a different time in an other node... check that your PC time and timezone is correct or you will be Blacklisted! '+
            'Your time: ' + TimeToStr(now) + ' - ' + Client.ClientRemoteAddr + ' time: ' + TimeToStr(UnivDateTime2LocalDateTime( UnixToUnivDateTime(connection_ts))) + ' Difference: ' + inttostr(FLastKnownTimestampDiff) + ' seconds. '+
            '(If this message appears on each connection, then you have a bad configured time, if not, do nothing)' );
        end;
      end;
    end else
    begin
      Result := true;
    end;
  end;
*)
var
  op : TPCOperationsComp;
  errors : AnsiString;
  connection_has_a_server : Word;
  i, c : Integer;
  nsa : TNodeServerAddress;
  connection_ts : Cardinal;
  Duplicate : TNetConnection;
  RawAccountKey : TRawBytes;
  other_version : AnsiString;
Begin
  FRemoteAccumulatedWork := 0;
  op := TPCOperationsComp.Create(Nil);
  try
    DataBuffer.Position := 0;
    if DataBuffer.Read(connection_has_a_server, 2) < 2 then
    begin
      DisconnectInvalidClient(false, 'Invalid data on buffer: ' + TNetData.HeaderDataToText(HeaderData));
      exit;
    end;
    if TStreamOp.ReadAnsiString(DataBuffer, RawAccountKey) < 0 then
    begin
      DisconnectInvalidClient(false, 'Invalid data on buffer. No Public key: ' + TNetData.HeaderDataToText(HeaderData));
      exit;
    end;
    FClientPublicKey := TAccountComp.RawString2Accountkey(RawAccountKey);
    if not TAccountComp.IsValidAccountKey(FClientPublicKey, errors) then
    begin
      DisconnectInvalidClient(false, 'Invalid Public key: ' + TNetData.HeaderDataToText(HeaderData) + ' errors: ' + errors);
      exit;
    end;
    if DataBuffer.Read(connection_ts, 4) < 4 then
    begin
      DisconnectInvalidClient(false, 'Invalid data on buffer. No TS: ' + TNetData.HeaderDataToText(HeaderData));
      exit;
    end;
    FLastKnownTimestampDiff := Int64(connection_ts) - Int64(UnivDateTimeToUnix( DateTime2UnivDateTime(now)));
    // Check valid time
    {
    if not IsValidTime(connection_ts) then
    begin
      DisconnectInvalidClient(false, 'Invalid remote timestamp. Difference:' + inttostr(FLastKnownTimestampDiff) + ' > ' + inttostr(CT_MaxSecondsDifferenceOfNetworkNodes));
    end;
    }
    if (connection_has_a_server > 0) and (not SameText(Client.RemoteHost, 'localhost')) and (not SameText(Client.RemoteHost, '127.0.0.1'))
      and (not SameText('192.168.', Copy(Client.RemoteHost, 1, 8)))
      and (not SameText('10.', Copy(Client.RemoteHost, 1, 3)))
      and (not TAccountComp.Equal(FClientPublicKey, TNetData.NetData.FNodePrivateKey.PublicKey)) then
    begin
      nsa := CT_TNodeServerAddress_NUL;
      nsa.ip := Client.RemoteHost;
      nsa.port := connection_has_a_server;
      // BUG corrected 1.1.1: nsa.last_connection_by_server := UnivDateTimeToUnix(DateTime2UnivDateTime(now));
      nsa.last_connection := UnivDateTimeToUnix(DateTime2UnivDateTime(now));
      TNetData.NetData.AddServer(nsa);
    end;

    if op.LoadBlockFromStream(DataBuffer, errors) then
    begin
      FRemoteOperationBlock := op.OperationBlock;
      if (DataBuffer.Size-DataBuffer.Position >= 4) then
      begin
        DataBuffer.Read(c, 4);
        for i := 1 to c do
        begin
          nsa := CT_TNodeServerAddress_NUL;
          TStreamOp.ReadAnsiString(DataBuffer, nsa.ip);
          DataBuffer.Read(nsa.port, 2);
          DataBuffer.Read(nsa.last_connection_by_server, 4);
          TNetData.NetData.AddServer(nsa);
        end;
        if TStreamOp.ReadAnsiString(DataBuffer, other_version) >= 0 then
        begin
          // Captures version
          ClientAppVersion := other_version;
          if (DataBuffer.Size-DataBuffer.Position >= SizeOf(FRemoteAccumulatedWork)) then
          begin
            DataBuffer.Read(FRemoteAccumulatedWork, SizeOf(FRemoteAccumulatedWork));
            TLog.NewLog(ltdebug, ClassName, 'Received HELLO with height: ' + inttostr(op.OperationBlock.block) + ' Accumulated work ' + IntToStr(FRemoteAccumulatedWork));
          end;
        end;
        //
        if (FRemoteAccumulatedWork > TNode.Node.Bank.SafeBox.WorkSum) Or
          ((FRemoteAccumulatedWork = 0) and (TNetData.NetData.FMaxRemoteOperationBlock.block < FRemoteOperationBlock.block)) then
        begin
          TNetData.NetData.FMaxRemoteOperationBlock := FRemoteOperationBlock;
          if TPCThread.ThreadClassFound(TThreadGetNewBlockChainFromClient, nil) < 0 then
          begin
            TThreadGetNewBlockChainFromClient.Create(false).FreeOnTerminate := true;
          end;
        end;
      end;

      TLog.NewLog(ltdebug, Classname, 'Hello received: ' + TPCOperationsComp.OperationBlockToText(FRemoteOperationBlock));
      if (HeaderData.header_type in [ntp_request, ntp_response]) then
      begin
        // Response:
        if (HeaderData.header_type = ntp_request) then
        begin
          Send_Hello(ntp_response, HeaderData.request_id);
        end;
        if (TAccountComp.Equal(FClientPublicKey, TNetData.NetData.FNodePrivateKey.PublicKey)) then
        begin
          DisconnectInvalidClient(true, 'MySelf disconnecting...');
          exit;
        end;
        Duplicate := TNetData.NetData.FindConnectionByClientRandomValue(Self);
        if (Duplicate <> Nil) and (Duplicate.Connected) then
        begin
          DisconnectInvalidClient(true, 'Duplicate connection with ' + Duplicate.ClientRemoteAddr);
          exit;
        end;
        TNetData.NetData.NotifyReceivedHelloMessage;
      end
      else
      begin
        DisconnectInvalidClient(false, 'Invalid header type > ' + TNetData.HeaderDataToText(HeaderData));
      end;
    end else
    begin
      TLog.NewLog(lterror, Classname, 'Error decoding operations of HELLO: ' + errors);
      DisconnectInvalidClient(false, 'Error decoding operations of HELLO: ' + errors);
    end;
  finally
    op.Free;
  end;
end;

procedure TNetConnection.DoProcess_Message(HeaderData: TNetHeaderData; DataBuffer: TStream);
var
  errors : AnsiString;
  decrypted, messagecrypted : AnsiString;
  DoDisconnect : boolean;
begin
  errors := '';
  DoDisconnect := true;
  try
    if HeaderData.header_type <> ntp_autosend then
    begin
      errors := 'Not autosend';
      exit;
    end;
    if TStreamOp.ReadAnsiString(DataBuffer, messagecrypted) < 0 then
    begin
      errors := 'Invalid message data';
      exit;
    end;
    if not ECIESDecrypt(TNetData.NetData.FNodePrivateKey.EC_OpenSSL_NID, TNetData.NetData.FNodePrivateKey.PrivateKey, false, messagecrypted, decrypted) then
    begin
      errors := 'Error on decrypting message';
      exit;
    end;

    DoDisconnect := false;
    if TCrypto.IsHumanReadable(decrypted) then
      TLog.NewLog(ltinfo, Classname, 'Received new message from ' + ClientRemoteAddr + ' Message (' + inttostr(length(decrypted)) + ' bytes): ' + decrypted)
    else
      TLog.NewLog(ltinfo, Classname, 'Received new message from ' + ClientRemoteAddr + ' Message (' + inttostr(length(decrypted)) + ' bytes) in hexadecimal: ' + TCrypto.ToHexaString(decrypted));
    try
      TNode.Node.NotifyNetClientMessage(Self, decrypted);
    except
      on E:Exception do
      begin
        TLog.NewLog(lterror, Classname, 'Error processing received message. ' + E.ClassName + ' ' + E.Message);
      end;
    end;
  finally
    if DoDisconnect then
    begin
      DisconnectInvalidClient(false, errors + ' > ' + TNetData.HeaderDataToText(HeaderData) + ' BuffSize: ' + inttostr(DataBuffer.Size));
    end;
  end;
end;

procedure TNetConnection.DoProcess_NewBlock(HeaderData: TNetHeaderData; DataBuffer: TStream);
var
  bacc : TBlockAccount;
  op : TPCOperationsComp;
  errors : AnsiString;
  DoDisconnect : Boolean;
begin
  errors := '';
  DoDisconnect := true;
  try
    if HeaderData.header_type <> ntp_autosend then
    begin
      errors := 'Not autosend';
      exit;
    end;
    op := TPCOperationsComp.Create(nil);
    try
      op.bank := TNode.Node.Bank;
      if not op.LoadBlockFromStream(DataBuffer, errors) then
      begin
        errors := 'Error decoding new account: ' + errors;
        exit;
      end else
      begin
        DoDisconnect := false;
        if DataBuffer.Size - DataBuffer.Position >= SizeOf(FRemoteAccumulatedWork) then
        begin
          DataBuffer.Read(FRemoteAccumulatedWork, SizeOf(FRemoteAccumulatedWork));
          TLog.NewLog(ltdebug, ClassName, 'Received NEW BLOCK with height: ' + inttostr(op.OperationBlock.block) + ' Accumulated work ' + IntToStr(FRemoteAccumulatedWork));
        end
        else
          FRemoteAccumulatedWork := 0;
        FRemoteOperationBlock := op.OperationBlock;
        //
        if FRemoteAccumulatedWork = 0 then
        begin
          // Old version. No data
          if (op.OperationBlock.block > TNode.Node.Bank.BlocksCount) then
          begin
            TNetData.NetData.GetNewBlockChainFromClient(Self, Format('BlocksCount:%d > my BlocksCount:%d', [op.OperationBlock.block + 1, TNode.Node.Bank.BlocksCount]));
          end else
          if (op.OperationBlock.block = TNode.Node.Bank.BlocksCount) then
          begin
            // New block candidate:
            if not TNode.Node.AddNewBlockChain(Self, op, bacc, errors) then
            begin
              // Received a new invalid block... perhaps I'm an orphan blockchain
              TNetData.NetData.GetNewBlockChainFromClient(Self, 'Has a distinct block. ' + errors);
            end;
          end;
        end else
        begin
          if (FRemoteAccumulatedWork > TNode.Node.Bank.SafeBox.WorkSum) then
          begin
            if (op.OperationBlock.block = TNode.Node.Bank.BlocksCount) then
            begin
              // New block candidate:
              if not TNode.Node.AddNewBlockChain(Self, op, bacc, errors) then
              begin
                // Received a new invalid block... perhaps I'm an orphan blockchain
                TNetData.NetData.GetNewBlockChainFromClient(Self, 'Higher Work with same block height. I''m a orphan blockchain candidate');
              end;
            end else
            begin
              // Received a new higher work
              TNetData.NetData.GetNewBlockChainFromClient(Self, Format('Higher Work and distinct blocks count. Need to download BlocksCount:%d  my BlocksCount:%d', [op.OperationBlock.block + 1, TNode.Node.Bank.BlocksCount]));
            end;
          end;
        end;
      end;
    finally
      op.Free;
    end;
  finally
    if DoDisconnect then
    begin
      DisconnectInvalidClient(false, errors + ' > ' + TNetData.HeaderDataToText(HeaderData) + ' BuffSize: ' + inttostr(DataBuffer.Size));
    end;
  end;
end;

function TNetConnection.DoSendAndWaitForResponse(operation: Word;
  RequestId: Integer; SendDataBuffer, ReceiveDataBuffer: TStream;
  MaxWaitTime: Cardinal; var HeaderData: TNetHeaderData): Boolean;
var
  tc : Cardinal;
  was_waiting_for_response : Boolean;
  l : TList;
  i : Integer;
  iDebugStep : Integer;
begin
  iDebugStep := 0;
  try
    Result := false;
    HeaderData := CT_NetHeaderData;
    if FIsWaitingForResponse then
    begin
      TLog.NewLog(ltdebug, Classname, 'Is waiting for response ...');
      exit;
    end;
    iDebugStep := 100;
    if not Assigned(FTcpIpClient) then
      exit;
    if not Client.Connected then
      exit;
    iDebugStep := 110;
    TPCThread.ProtectEnterCriticalSection(Self, FNetLock);
    try
      iDebugStep := 120;
      was_waiting_for_response := RequestId > 0;
      try
        if was_waiting_for_response then
        begin
          iDebugStep := 200;
          FIsWaitingForResponse := true;
          Send(ntp_request, operation, 0, RequestId, SendDataBuffer);
        end;
        iDebugStep := 300;
        tc := GetTickCount;
        Repeat
          iDebugStep := 400;
          if (ReadTcpClientBuffer(MaxWaitTime, HeaderData, ReceiveDataBuffer)) then
          begin
            iDebugStep := 500;
            l := TNetData.NetData.NodeServersAddresses.LockList;
            try
              iDebugStep := 600;
              for i := 0 to l.Count - 1 do
              begin
                if PNodeServerAddress( l[i] )^.netConnection = Self then
                begin
                  PNodeServerAddress( l[i] )^.last_connection := (UnivDateTimeToUnix(DateTime2UnivDateTime(now)));
                  PNodeServerAddress( l[i] )^.total_failed_attemps_to_connect := 0;
                end;
              end;
            finally
              iDebugStep := 700;
              TNetData.netData.NodeServersAddresses.UnlockList;
            end;
            iDebugStep := 800;
            TLog.NewLog(ltDebug, Classname, 'Received ' + CT_NetTransferType[HeaderData.header_type] + ' operation:' + TNetData.OperationToText(HeaderData.operation) + ' id:' + Inttostr(HeaderData.request_id) + ' Buffer size:' + Inttostr(HeaderData.buffer_data_length) );
            if (RequestId = HeaderData.request_id) and (HeaderData.header_type = ntp_response) then
            begin
              Result := true;
            end else
            begin
              iDebugStep := 1000;
              case HeaderData.operation of
                CT_NetOp_Hello : DoProcess_Hello(HeaderData, ReceiveDataBuffer);
                CT_NetOp_Message : DoProcess_Message(HeaderData, ReceiveDataBuffer);
                CT_NetOp_GetBlocks :
                begin
                  if HeaderData.header_type = ntp_request then
                    DoProcess_GetBlocks_Request(HeaderData, ReceiveDataBuffer)
                  else if HeaderData.header_type = ntp_response then
                    DoProcess_GetBlocks_Response(HeaderData, ReceiveDataBuffer)
                  else
                    DisconnectInvalidClient(false, 'Not resquest or response: ' + TNetData.HeaderDataToText(HeaderData));
                end;
                CT_NetOp_GetOperationsBlock :
                begin
                  if HeaderData.header_type = ntp_request then
                    DoProcess_GetOperationsBlock_Request(HeaderData, ReceiveDataBuffer)
                  else
                    TLog.NewLog(ltdebug, Classname, 'Received old response of: ' + TNetData.HeaderDataToText(HeaderData));
                end;
                CT_NetOp_NewBlock : DoProcess_NewBlock(HeaderData, ReceiveDataBuffer);
                CT_NetOp_AddOperations : DoProcess_AddOperations(HeaderData, ReceiveDataBuffer);
              else
                DisconnectInvalidClient(false, 'Invalid operation: ' + TNetData.HeaderDataToText(HeaderData));
              end;
            end;
          end
          else
            sleep(1);
          iDebugStep := 900;
        until (Result) or (GetTickCount > (MaxWaitTime + tc));
      finally
        if was_waiting_for_response then
          FIsWaitingForResponse := false;
      end;
      iDebugStep := 990;
    finally
      FNetLock.Release;
    end;
  except
    on E:Exception do
    begin
      E.Message := E.Message + ' DoSendAndWaitForResponse step ' + Inttostr(iDebugStep);
      raise;
    end;
  end;
end;

procedure TNetConnection.FinalizeConnection;
begin
  if FDoFinalizeConnection then
    exit;
  TLog.NewLog(ltdebug, ClassName, 'Executing FinalizeConnection to ' + ClientRemoteAddr);
  FDoFinalizeConnection := true;
end;

function TNetConnection.GetClient: TNetTcpIpClient;
begin
  if not Assigned(FTcpIpClient) then
  begin
    TLog.NewLog(ltError, Classname, 'TcpIpClient = NIL');
    raise Exception.Create('TcpIpClient = NIL');
  end;
  Result := FTcpIpClient;
end;

function TNetConnection.GetConnected: Boolean;
begin
  Result := Assigned(FTcpIpClient) and (FTcpIpClient.Connected);
end;

procedure TNetConnection.Notification(AComponent: TComponent; Operation: TOperation);
begin
  inherited;
  if (Operation = opRemove) and (AComponent = FTcpIpClient) then
  begin
    FTcpIpClient := nil;
  end;
end;

function TNetConnection.ReadTcpClientBuffer(MaxWaitMiliseconds: Cardinal; var HeaderData: TNetHeaderData; BufferData: TStream): Boolean;
var
  auxstream : TMemoryStream;
  tc : Cardinal;
  last_bytes_read, t_bytes_read : Int64;
  //
  IsValidHeaderButNeedMoreData : Boolean;
  deletedBytes : Int64;
begin
  t_bytes_read := 0;
  Result := false;
  HeaderData := CT_NetHeaderData;
  BufferData.Size := 0;
  TPCThread.ProtectEnterCriticalSection(Self, FNetLock);
  try
    tc := GetTickCount;
    repeat
      if not Connected then
        exit;
      if not Client.Connected then
        exit;
      last_bytes_read := 0;
      FClientBufferRead.Position := 0;
      Result := TNetData.ExtractHeaderInfo(FClientBufferRead, HeaderData, BufferData, IsValidHeaderButNeedMoreData);
      if Result then
      begin
        FNetProtocolVersion := HeaderData.protocol;
        // Build 1.0.4 accepts net protocol 1 and 2
        if HeaderData.protocol.protocol_version > CT_NetProtocol_Available then
        begin
          TNode.Node.NotifyNetClientMessage(nil, 'Detected a higher Net protocol version at '+
            ClientRemoteAddr + ' (v ' + inttostr(HeaderData.protocol.protocol_version) + ' ' + inttostr(HeaderData.protocol.protocol_available) + ') '+
            '... check that your version is Ok! Visit official download website for possible updates: https://github.com/blaisecoin/blaisecoin/releases');
          DisconnectInvalidClient(false, Format('Invalid Net protocol version found: %d available: %d', [HeaderData.protocol.protocol_version, HeaderData.protocol.protocol_available]));
          Result := false;
          exit;
        end else
        begin
          if (FNetProtocolVersion.protocol_available > CT_NetProtocol_Available) and (not FAlertedForNewProtocolAvailable) then
          begin
            FAlertedForNewProtocolAvailable := true;
            TNode.Node.NotifyNetClientMessage(nil, 'Detected a new Net protocol version at '+
              ClientRemoteAddr + ' (v ' + inttostr(HeaderData.protocol.protocol_version) + ' ' + inttostr(HeaderData.protocol.protocol_available) + ') '+
              '... Visit official download website for possible updates: https://github.com/blaisecoin/blaisecoin/releases');
          end;
          // Remove data from buffer and save only data not processed (higher than stream.position)
          auxstream := TMemoryStream.Create;
          try
            if FClientBufferRead.Position < FClientBufferRead.Size then
            begin
              auxstream.CopyFrom(FClientBufferRead, FClientBufferRead.Size-FClientBufferRead.Position);
            end;
            FClientBufferRead.Size := 0;
            FClientBufferRead.CopyFrom(auxstream, 0);
          finally
            auxstream.Free;
          end;
        end;
      end else
      begin
        if not Client.WaitForData(100) then
        begin
          exit;
        end;

        auxstream := (Client as TBufferedNetTcpIpClient).ReadBufferLock;
        try
          last_bytes_read := auxstream.size;
          if last_bytes_read > 0 then
          begin
            FLastDataReceivedTS := GetTickCount;
            FRandomWaitSecondsSendHello := 90 + Random(60);

            FClientBufferRead.Position := FClientBufferRead.size; // Go to the end
            auxstream.Position := 0;
            FClientBufferRead.CopyFrom(auxstream, last_bytes_read);
            FClientBufferRead.Position := 0;
            auxstream.Size := 0;
            inc(t_bytes_read, last_bytes_read);
          end;
        finally
          (Client as TBufferedNetTcpIpClient).ReadBufferUnlock;
        end;
      end;
    until (Result) or ((GetTickCount > (tc + MaxWaitMiliseconds)) and (last_bytes_read = 0));
  finally
    try
      if (Connected) then
      begin
        if (not Result) and (FClientBufferRead.Size > 0) and (not IsValidHeaderButNeedMoreData) then
        begin
          deletedBytes := FClientBufferRead.Size;
          TLog.NewLog(lterror, ClassName, Format('Deleting %d bytes from TcpClient buffer of %s after max %d miliseconds. Passed: %d',
            [deletedBytes, Client.ClientRemoteAddr, MaxWaitMiliseconds, GetTickCount-tc]));
          FClientBufferRead.Size := 0;
          DisconnectInvalidClient(false, 'Invalid data received in buffer (' + inttostr(deletedBytes) + ' bytes)');
        end;
      end;
    finally
      FNetLock.Release;
    end;
  end;
  if t_bytes_read > 0 then
  begin
    if not FHasReceivedData then
    begin
      FHasReceivedData := true;
      if (Self is TNetClient) then
        TNetData.NetData.IncStatistics(0, 0, 0, 1, t_bytes_read, 0)
      else
        TNetData.NetData.IncStatistics(0, 0, 0, 0, t_bytes_read, 0);
    end else
    begin
      TNetData.NetData.IncStatistics(0, 0, 0, 0, t_bytes_read, 0);
    end;
  end;
  if (Result) and (HeaderData.header_type = ntp_response) then
  begin
    TNetData.NetData.UnRegisterRequest(Self, HeaderData.operation, HeaderData.request_id);
  end;
end;

procedure TNetConnection.Send(NetTranferType: TNetTransferType; operation, errorcode: Word; request_id: Integer; DataBuffer: TStream);
var l : Cardinal;
   w : Word;
  Buffer : TStream;
  s : AnsiString;
begin
  Buffer := TMemoryStream.Create;
  try
    l := CT_MagicNetIdentification;
    Buffer.Write(l, 4);
    case NetTranferType of
      ntp_request:
      begin
        w := CT_MagicRequest;
        Buffer.Write(w, 2);
        Buffer.Write(operation, 2);
        w := 0;
        Buffer.Write(w, 2);
        Buffer.Write(request_id, 4);
      end;
      ntp_response:
      begin
        w := CT_MagicResponse;
        Buffer.Write(w, 2);
        Buffer.Write(operation, 2);
        Buffer.Write(errorcode, 2);
        Buffer.Write(request_id, 4);
      end;
      ntp_autosend:
      begin
        w := CT_MagicAutoSend;
        Buffer.Write(w, 2);
        Buffer.Write(operation, 2);
        w := errorcode;
        Buffer.Write(w, 2);
        l := 0;
        Buffer.Write(l, 4);
      end
    else
      raise Exception.Create('Invalid encoding');
    end;
    l := CT_NetProtocol_Version;
    Buffer.Write(l, 2);
    l := CT_NetProtocol_Available;
    Buffer.Write(l, 2);
    if Assigned(DataBuffer) then
    begin
      l := DataBuffer.Size;
      Buffer.Write(l, 4);
      DataBuffer.Position := 0;
      Buffer.CopyFrom(DataBuffer, DataBuffer.Size);
      s := '(Data:' + inttostr(DataBuffer.Size) + 'b) ';
    end else
    begin
      l := 0;
      Buffer.Write(l, 4);
      s := '';
    end;
    Buffer.Position := 0;
    TPCThread.ProtectEnterCriticalSection(Self, FNetLock);
    try
      TLog.NewLog(ltDebug, Classname, 'Sending: ' + CT_NetTransferType[NetTranferType] + ' operation:'+
        TNetData.OperationToText(operation) + ' id:' + Inttostr(request_id) + ' errorcode:' + InttoStr(errorcode)+
        ' Size:' + InttoStr(Buffer.Size) + 'b ' + s+'to '+
        ClientRemoteAddr);
      (Client as TBufferedNetTcpIpClient).WriteBufferToSend(Buffer);
      FLastDataSendedTS := GetTickCount;
      FRandomWaitSecondsSendHello := 90 + Random(60);
    finally
      FNetLock.Release;
    end;
    TNetData.NetData.IncStatistics(0, 0, 0, 0, 0, Buffer.Size);
  finally
    Buffer.Free;
  end;
end;

procedure TNetConnection.SendError(NetTranferType: TNetTransferType; operation, request_id, error_code: Integer; error_text: AnsiString);
var buffer : TStream;
begin
  buffer := TMemoryStream.Create;
  try
    TStreamOp.WriteAnsiString(buffer, error_text);
    Send(NetTranferType, operation, error_code, request_id, buffer);
  finally
    buffer.Free;
  end;
end;

function TNetConnection.Send_AddOperations(Operations : TOperationsHashTree) : Boolean;
var
  data : TMemoryStream;
  c1, request_id : Cardinal;
  i : Integer;
  optype : Byte;
begin
  Result := false;
  data := TMemoryStream.Create;
  try
    request_id := TNetData.NetData.NewRequestId;
    c1 := Operations.OperationsCount;
    data.Write(c1, 4);
    for i := 0 to Operations.OperationsCount-1 do
    begin
      optype := Operations.GetOperation(i).OpType;
      data.Write(optype, 1);
      Operations.GetOperation(i).SaveToStream(data);
    end;
    Send(ntp_autosend, CT_NetOp_AddOperations, 0, request_id, data);
    Result := Connected;
  finally
    data.Free;
  end;
end;

function TNetConnection.Send_GetBlocks(StartAddress, quantity : Cardinal; var request_id : Cardinal) : Boolean;
var data : TMemoryStream;
  c1, c2 : Cardinal;
begin
  Result := false;
  request_id := 0;
  if (FRemoteOperationBlock.block < TNetData.NetData.Bank.BlocksCount) or (FRemoteOperationBlock.block = 0) then exit;
  // First receive operations from
  data := TMemoryStream.Create;
  try
    if TNetData.NetData.Bank.BlocksCount = 0 then
      c1 := 0
    else
      c1 := StartAddress;
    if (quantity = 0) then
    begin
      if FRemoteOperationBlock.block > 0 then
        c2 := FRemoteOperationBlock.block
      else
        c2 := c1 + 100;
    end else c2 := c1 + quantity-1;
    // Build 1.0.5 BUG - Always query for ONLY 1 if Build is lower or equal to 1.0.5
    if ((FClientAppVersion = '') or ( (length(FClientAppVersion) = 5) and (FClientAppVersion <= '1.0.5') )) then
    begin
      c2 := c1;
    end;
    data.Write(c1, 4);
    data.Write(c2, 4);
    request_id := TNetData.NetData.NewRequestId;
    TNetData.NetData.RegisterRequest(Self, CT_NetOp_GetBlocks, request_id);
    TLog.NewLog(ltdebug, ClassName, Format('Send GET BLOCKS start:%d quantity:%d (from:%d to %d)', [StartAddress, quantity, StartAddress, quantity + StartAddress]));
    FIsDownloadingBlocks := quantity > 1;
    Send(ntp_request, CT_NetOp_GetBlocks, 0, request_id, data);
    Result := Connected;
  finally
    data.Free;
  end;
end;

function TNetConnection.Send_Hello(NetTranferType : TNetTransferType; request_id : Integer) : Boolean;
  { HELLO command:
    - Operation stream
    - My Active server port (0 if no active). (2 bytes)
    - A Random Longint (4 bytes) to check if its myself connection to my server socket
    - My Unix Timestamp (4 bytes)
    - Registered node servers count
      (For each)
      - ip (string)
      - port (2 bytes)
      - last_connection UTS (4 bytes)
    - My Server port (2 bytes)
    - if this is a response:
      - if remote operation block is lower than me:
        - Send My Operation Stream in the same block thant requester
      }
var data : TStream;
  i : Integer;
  op : TPCOperationsComp;
  nsa : TNodeServerAddress;
  nsarr : TNodeServerAddressArray;
  w : Word;
  currunixtimestamp : Cardinal;
begin
  Result := false;
  if not Connected then
    exit;
  // Send Hello command:
  data := TMemoryStream.Create;
  try
    if NetTranferType = ntp_request then
    begin
      TNetData.NetData.RegisterRequest(Self, CT_NetOp_Hello, request_id);
    end;
    if TNode.Node.NetServer.Active then
      w := TNode.Node.NetServer.Port
    else w := 0;
    // Save active server port (2 bytes). 0 = No active server port
    data.Write(w, 2);
    // Save My connection public key
    TStreamOp.WriteAnsiString(data, TAccountComp.AccountKey2RawString(TNetData.NetData.FNodePrivateKey.PublicKey));
    // Save my Unix timestamp (4 bytes)
    currunixtimestamp := UnivDateTimeToUnix(DateTime2UnivDateTime(now));
    data.Write(currunixtimestamp, 4);
    // Save last operations block
    op := TPCOperationsComp.Create(nil);
    try
      if (TNode.Node.Bank.BlocksCount > 0) then
        TNode.Node.Bank.LoadOperations(op, TNode.Node.Bank.BlocksCount-1);
      op.SaveBlockToStream(true, data);
    finally
      op.free;
    end;
    nsarr := TNetData.NetData.GetValidNodeServers(true, 20);
    i := length(nsarr);
    data.Write(i, 4);
    for i := 0 to High(nsarr) do
    begin
      nsa := nsarr[i];
      TStreamOp.WriteAnsiString(data, nsa.ip);
      data.Write(nsa.port, 2);
      data.Write(nsa.last_connection, 4);
    end;
    // Send client version
    TStreamOp.WriteAnsiString(data, CT_ClientAppVersion{$IFDEF LINUX} + 'l'{$ELSE} + 'w'{$ENDIF}{$IFDEF FPC}{$IFDEF LCL} + 'L'{$ELSE} + 'F'{$ENDIF}{$ENDIF});
    // Build 1.5 send accumulated work
    data.Write(TNode.Node.Bank.SafeBox.WorkSum, SizeOf(TNode.Node.Bank.SafeBox.WorkSum));
    //
    Send(NetTranferType, CT_NetOp_Hello, 0, request_id, data);
    Result := Client.Connected;
  finally
    data.Free;
  end;
end;

function TNetConnection.Send_Message(const TheMessage: AnsiString): Boolean;
var
  data : TStream;
  cyp : TRawBytes;
begin
  Result := false;
  if not Connected then
    exit;
  data := TMemoryStream.Create;
  try
    // Cypher message:
    cyp := ECIESEncrypt(FClientPublicKey, TheMessage);
    TStreamOp.WriteAnsiString(data, cyp);
    Send(ntp_autosend, CT_NetOp_Message, 0, 0, data);
    Result := true;
  finally
    data.Free;
  end;
end;

function TNetConnection.Send_NewBlockFound: Boolean;
var
  data : TStream;
  request_id : Integer;
  op : TPCOperationsComp;
begin
  Result := false;
  if TNetData.NetData.Bank.BlocksCount = 0 then
    exit;
  if Connected then
  begin
    // Checking if operationblock is the same to prevent double messaging...
    if (TPCOperationsComp.EqualsOperationBlock(FRemoteOperationBlock, TNode.Node.Bank.LastOperationBlock)) then
      exit;
    // Send Hello command:
    data := TMemoryStream.Create;
    try
      request_id := TNetData.NetData.NewRequestId;
      op := TPCOperationsComp.Create(nil);
      try
        op.bank := TNetData.NetData.Bank;
        if not TNetData.NetData.Bank.LoadOperations(op, TNetData.NetData.Bank.BlocksCount-1) then
        begin
          TLog.NewLog(lterror, Classname, 'Error on Send_NewBlockFound. Cannot load BlockOperations ' + inttostr(TNetData.NetData.Bank.BlocksCount-1));
          exit;
        end;
        op.SaveBlockToStream(false, data);
        // Build 1.5 sending Accumulated work
        data.Write(op.bank.SafeBox.WorkSum, SizeOf(op.bank.SafeBox.WorkSum));
        Send(ntp_autosend, CT_NetOp_NewBlock, 0, request_id, data);
      finally
        op.free;
      end;
    finally
      data.Free;
    end;
    Result := Connected;
  end;
end;

procedure TNetConnection.SetClient(const Value: TNetTcpIpClient);
var old : TNetTcpIpClient;
begin
  if FTcpIpClient <> Value then
  begin
    if Assigned(FTcpIpClient) then
    begin
      FTcpIpClient.RemoveFreeNotification(Self);
    end;
    TNetData.NetData.UnRegisterRequest(Self, 0, 0);
    // Build 1.0.4 -> Prior to free, must ensure FClient is valid
    old := FTcpIpClient;
    FTcpIpClient := Value;
    if Assigned(old) then
    begin
      if old.Owner = Self then
      begin
        old.Free;
      end;
    end;
  end;
  if Assigned(FTcpIpClient) then
  begin
    FTcpIpClient.FreeNotification(Self);
    FTcpIpClient.OnConnect := TcpClient_OnConnect;
    FTcpIpClient.OnDisconnect := TcpClient_OnDisconnect;
  end;
  TNetData.NetData.NotifyNetConnectionUpdated;
end;

procedure TNetConnection.SetConnected(const Value: Boolean);
begin
  if (Value = GetConnected) then
    exit;
  if Value then
    ConnectTo(Client.RemoteHost, Client.RemotePort)
  else
    Client.Disconnect;
end;

procedure TNetConnection.TcpClient_OnConnect(Sender: TObject);
begin
  TNetData.NetData.IncStatistics(1, 0, 1, 0, 0, 0);
  TLog.NewLog(ltInfo, Classname, 'Connected to a server ' + ClientRemoteAddr);
  TNetData.NetData.NotifyNetConnectionUpdated;
end;

procedure TNetConnection.TcpClient_OnDisconnect(Sender: TObject);
begin
  if self is TNetServerClient then
    TNetData.NetData.IncStatistics(-1, -1, 0, 0, 0, 0)
  else
  begin
    if FHasReceivedData then
      TNetData.NetData.IncStatistics(-1, 0, -1, -1, 0, 0)
    else
      TNetData.NetData.IncStatistics(-1, 0, -1, 0, 0, 0);
  end;
  TLog.NewLog(ltInfo, Classname, 'Disconnected from ' + ClientRemoteAddr);
  TNetData.NetData.NotifyNetConnectionUpdated;
end;

{ TNetClientThread }

procedure TNetClientThread.BCExecute;
begin
  while (not Terminated) do
  begin
    if FNetClient.Connected then
    begin
      FNetClient.DoProcessBuffer;
    end;
    Sleep(1);
  end;
end;

constructor TNetClientThread.Create(NetClient: TNetClient; AOnTerminateThread : TNotifyEvent);
begin
  FNetClient := NetClient;
  inherited Create(false);
  OnTerminate := AOnTerminateThread;
end;

{ TNetClient }

constructor TNetClient.Create(AOwner: TComponent);
begin
  inherited;
  FNetClientThread := TNetClientThread.Create(Self, OnNetClientThreadTerminated);
  FNetClientThread.FreeOnTerminate := false;
end;

destructor TNetClient.Destroy;
begin
  TLog.NewLog(ltdebug, Classname, 'Starting TNetClient.Destroy');
  FNetClientThread.OnTerminate := nil;
  if not FNetClientThread.Terminated then
  begin
    FNetClientThread.Terminate;
    FNetClientThread.WaitFor;
  end;
  FreeAndNil(FNetClientThread);
  inherited;
end;

procedure TNetClient.OnNetClientThreadTerminated(Sender: TObject);
begin
  // Close connection
  if TNetData.NetData.ConnectionExistsAndActive(Self) then begin
    Connected := false;
  end;
end;

{ TThreadDiscoverConnection }

procedure TThreadDiscoverConnection.BCExecute;
var
  NC : TNetClient;
  ok : Boolean;
  lns : TList;
  i : Integer;
  Pnsa : PNodeServerAddress;
begin
  if Terminated then
    exit;

  TLog.NewLog(ltInfo, Classname, 'Starting discovery of connection ' + FNodeServerAddress.ip + ':' + InttoStr(FNodeServerAddress.port));
  Pnsa := nil;
  DebugStep := 'Locking list';
  // Register attempt
  lns := TNetData.NetData.NodeServersAddresses.LockList;
  try
    DebugStep := 'Searching net client';
    i := TNetData.NetData.IndexOfNetClient(lns, FNodeServerAddress.ip, FNodeServerAddress.port);
    if i >= 0 then
    begin
      DebugStep := 'Searching client found';
      Pnsa := PNodeServerAddress(lns[i]);
      Pnsa.last_attempt_to_connect := Now;
      Inc(Pnsa.total_failed_attemps_to_connect);
    end;
  finally
    TNetData.NetData.NodeServersAddresses.UnlockList;
  end;
  DebugStep := 'Synchronizing notify';
  if Terminated then
    exit;
  TNetData.NetData.NotifyNodeServersUpdated;
  // Try to connect
  ok := false;
  DebugStep := 'Trying to connect';
  if Terminated then
    exit;
  NC := TNetClient.Create(Nil);
  try
    DebugStep := 'Connecting';
    if NC.ConnectTo(FNodeServerAddress.ip, FNodeServerAddress.port) then
    begin
      if Terminated then
        exit;
      Sleep(500);
      DebugStep := 'Is connected now?';
      if Terminated then
        exit;
      ok :=NC.Connected;
    end;
    if Terminated then
      exit;
  finally
    if not ok then
    begin
      DebugStep := 'Destroying non connected';
      NC.FinalizeConnection;
    end;
  end;
  DebugStep := 'Synchronizing notify final';
  if Terminated then
    exit;
  TNetData.NetData.NotifyNodeServersUpdated;
end;

constructor TThreadDiscoverConnection.Create(NodeServerAddress: TNodeServerAddress; NotifyOnTerminate : TNotifyEvent);
begin
  FNodeServerAddress := NodeServerAddress;
  inherited Create(true);
  OnTerminate := NotifyOnTerminate;
  FreeOnTerminate := true;
  Suspended := false;
end;

{ TThreadCheckConnections }

procedure TThreadCheckConnections.BCExecute;
var l : TList;
  i, nactive, ndeleted, ntotal, nserverclients : Integer;
  netconn : TNetConnection;
  netserverclientstop : TNetServerClient;
  aux : AnsiString;
  needother : Boolean;
  newstats : TNetStatistics;
begin
  FLastCheckTS := GetTickCount;
  while (not Terminated) do
  begin
    if ((GetTickCount > (FLastCheckTS + 1000)) and (not FNetData.FIsDiscoveringServers)) then
    begin
      nactive := 0;
      ndeleted := 0;
      ntotal := 0;
      nserverclients := 0;
      netserverclientstop := nil;
      needother := true;
      FLastCheckTS := GetTickCount;
      if (FNetData.FNetConnections.TryLockList(100, l)) then
      begin
        try
          ntotal := l.Count;
          newstats := CT_TNetStatistics_NUL;
          for i := l.Count-1 downto 0 do
          begin
            netconn := TNetConnection(l.Items[i]);
            if (netconn is TNetClient) then
            begin
              if (netconn.Connected) then
              begin
                inc(newstats.ServersConnections);
                if (netconn.FHasReceivedData) then
                  inc(newstats.ServersConnectionsWithResponse);
              end;
              if (not TNetClient(netconn).Connected) and (netconn.CreatedTime + EncodeTime(0, 0, 5, 0) < now) then
              begin
                // Free this!
                TNetClient(netconn).FinalizeConnection;
                inc(ndeleted);
              end
              else
                inc(nactive);
            end else if (netconn is TNetServerClient) then
            begin
              if (netconn.Connected) then
              begin
                inc(newstats.ClientsConnections);
              end;
              inc(nserverclients);
              if (not netconn.FDoFinalizeConnection) then
              begin
                // Build 1.0.9 BUG-101 Only disconnect old versions prior to 1.0.9
                if not assigned(netserverclientstop) then
                begin
                  netserverclientstop := TNetServerClient(netconn);
                  aux := Copy(netconn.FClientAppVersion, 1, 5);
                  needother := not ((aux = '1.0.6') or (aux = '1.0.7') or (aux = '1.0.8'));
                end else
                begin
                  aux := Copy(netconn.FClientAppVersion, 1, 5);
                  if ((aux = '1.0.6') or (aux = '1.0.7') or (aux = '1.0.8'))
                    and ((needother) or (netconn.CreatedTime < netserverclientstop.CreatedTime)) then
                  begin
                    needother := false;
                    netserverclientstop := TNetServerClient(netconn);
                  end;
                end;
              end;
            end;
          end;
          // Update stats:
          FNetData.FNetStatistics.ActiveConnections := newstats.ClientsConnections + newstats.ServersConnections;
          FNetData.FNetStatistics.ClientsConnections := newstats.ClientsConnections;
          FNetData.FNetStatistics.ServersConnections := newstats.ServersConnections;
          FNetData.FNetStatistics.ServersConnectionsWithResponse := newstats.ServersConnectionsWithResponse;
          // Must stop clients?
          if (nserverclients > CT_MaxServersConnected) and // This is to ensure there are more serverclients than clients
             ((nserverclients + nactive + ndeleted) >= CT_MaxClientsConnected) and (Assigned(netserverclientstop)) then
          begin
            TLog.NewLog(ltinfo, Classname, Format('Sending FinalizeConnection NetServerClients:%d Servers_active:%d Servers_deleted:%d', [nserverclients, nactive, ndeleted]));
            netserverclientstop.FinalizeConnection;
          end;
        finally
          FNetData.FNetConnections.UnlockList;
        end;
        if (nactive <= CT_MaxServersConnected) and (not Terminated) then
        begin
          // Discover
          FNetData.DiscoverServers;
        end;
      end;
    end;
    sleep(100);
  end;
end;

constructor TThreadCheckConnections.Create(NetData: TNetData);
begin
  FNetData := NetData;
  inherited Create(false);
end;

{ TThreadGetNewBlockChainFromClient }

procedure TThreadGetNewBlockChainFromClient.BCExecute;
var i, j, iMax : Integer;
  maxWork : UInt64;
  candidates : TList;
  lop : TOperationBlock;
  nc : TNetConnection;
begin
  // Search better candidates:
  candidates := TList.Create;
  try
    lop := CT_OperationBlock_NUL;
    TNetData.NetData.FMaxRemoteOperationBlock := CT_OperationBlock_NUL;
    // First round: Find by most work
    iMax := 0;
    maxWork := 0;
    j := TNetData.NetData.ConnectionsCountAll;
    for i := 0 to j - 1 do
    begin
      if TNetData.NetData.GetConnection(i, nc) then
      begin
        if (nc.FRemoteAccumulatedWork > maxWork) and (nc.FRemoteAccumulatedWork > TNode.Node.Bank.SafeBox.WorkSum) then
        begin
          maxWork := nc.FRemoteAccumulatedWork;
          iMax := i;
        end;
        // Preventing downloading
        if nc.FIsDownloadingBlocks then
          exit;
      end;
    end;
    if (maxWork > 0) then
    begin
      for i := 0 to j - 1 do
      begin
        if TNetData.NetData.GetConnection(i, nc) then
        begin
          if (nc.FRemoteAccumulatedWork >= maxWork) then
          begin
            candidates.Add(nc);
            lop := nc.FRemoteOperationBlock;
          end;
        end;
      end;
    end;
    // Second round: Find by most height
    if candidates.Count = 0 then
    begin
      for i := 0 to j - 1 do
      begin
        if (TNetData.NetData.GetConnection(i, nc)) then
        begin
          if (nc.FRemoteOperationBlock.block >= TNode.Node.Bank.BlocksCount) and
             (nc.FRemoteOperationBlock.block >= lop.block) then
          begin
             lop := nc.FRemoteOperationBlock;
          end;
        end;
      end;
      if (lop.block > 0) then
      begin
        for i := 0 to j - 1 do
        begin
          if (TNetData.NetData.GetConnection(i, nc)) then
          begin
            if (nc.FRemoteOperationBlock.block >= lop.block) then
            begin
              candidates.Add(nc);
            end;
          end;
        end;
      end;
    end;
    TNetData.NetData.FMaxRemoteOperationBlock := lop;
    if (candidates.Count > 0) then
    begin
      // Random a candidate
      i := 0;
      if (candidates.Count > 1) then
        i := Random(candidates.Count); // i = 0..count-1
      nc := TNetConnection(candidates[i]);
      TNetData.NetData.GetNewBlockChainFromClient(nc, Format('Candidate block: %d sum: %d', [nc.FRemoteOperationBlock.block, nc.FRemoteAccumulatedWork]));
    end;
  finally
    candidates.Free;
  end;
end;

{ TNetDataNotifyEventsThread }

procedure TNetDataNotifyEventsThread.BCExecute;
begin
  while (not Terminated) do
  begin
    if (FNotifyOnReceivedHelloMessage) or
       (FNotifyOnStatisticsChanged) or
       (FNotifyOnNetConnectionsUpdated) or
       (FNotifyOnNodeServersUpdated) or
       (FNotifyOnBlackListUpdated) then
    begin
      Synchronize(SynchronizedNotify);
    end;
    Sleep(10);
  end;
end;

constructor TNetDataNotifyEventsThread.Create(ANetData: TNetData);
begin
  FNetData := ANetData;
  FNotifyOnReceivedHelloMessage := false;
  FNotifyOnStatisticsChanged := false;
  FNotifyOnNetConnectionsUpdated := false;
  FNotifyOnNodeServersUpdated := false;
  FNotifyOnBlackListUpdated := false;
  inherited Create(false);
end;

procedure TNetDataNotifyEventsThread.SynchronizedNotify;
begin
  if Terminated then
    exit;
  if not Assigned(FNetData) then
    exit;

  if FNotifyOnReceivedHelloMessage then
  begin
    FNotifyOnReceivedHelloMessage := false;
    if Assigned(FNetData.FOnReceivedHelloMessage) then
      FNetData.FOnReceivedHelloMessage(FNetData);
  end;
  if FNotifyOnStatisticsChanged then
  begin
    FNotifyOnStatisticsChanged := false;
    if Assigned(FNetData.FOnStatisticsChanged) then
      FNetData.FOnStatisticsChanged(FNetData);
  end;
  if FNotifyOnNetConnectionsUpdated then
  begin
    FNotifyOnNetConnectionsUpdated := false;
    if Assigned(FNetData.FOnNetConnectionsUpdated) then
      FNetData.FOnNetConnectionsUpdated(FNetData);
  end;
  if FNotifyOnNodeServersUpdated then
  begin
    FNotifyOnNodeServersUpdated := false;
    if Assigned(FNetData.FOnNodeServersUpdated) then
      FNetData.FOnNodeServersUpdated(FNetData);
  end;
  if FNotifyOnBlackListUpdated then
  begin
    FNotifyOnBlackListUpdated := false;
    if Assigned(FNetData.FOnBlackListUpdated) then
      FNetData.FOnBlackListUpdated(FNetData);
  end;
end;

{ TNetClientsDestroyThread }

procedure TNetClientsDestroyThread.BCExecute;
var l, l_to_del : TList;
  i : Integer;
begin
  l_to_del := TList.Create;
  try
    while not Terminated do
    begin
      l_to_del.Clear;
      l := FNetData.NetConnections.LockList;
      try
        FTerminatedAllConnections := l.Count = 0;
        for i := 0 to l.Count-1 do
        begin
          if (TObject(l[i]) is TNetClient) and (not TNetConnection(l[i]).Connected) and (TNetConnection(l[i]).FDoFinalizeConnection) then
          begin
            l_to_del.Add(l[i]);
          end;
        end;
      finally
        FNetData.NetConnections.UnlockList;
      end;

      for i := 0 to l_to_del.Count - 1 do
      begin
        if FNetData.ConnectionLock(Self, TNetConnection(l_to_del[i]), 500) then
        begin
          try
            DebugStep := 'Destroying NetClient ' + TNetConnection(l_to_del[i]).ClientRemoteAddr;
            TNetConnection(l_to_del[i]).Free;
          finally
            // not Necessary because on Freeing then Lock is deleted.
            // -> TNetData.NetData.ConnectionUnlock(FNetClient);
          end;
        end;
      end;
      Sleep(100);
    end;
  finally
    l_to_del.Free;
  end;
end;

constructor TNetClientsDestroyThread.Create(NetData: TNetData);
begin
  FNetData := NetData;
  FTerminatedAllConnections := true;
  Inherited Create(false);
end;

procedure TNetClientsDestroyThread.WaitForTerminatedAllConnections;
begin
  while (not FTerminatedAllConnections) do
  begin
    TLog.NewLog(ltdebug, ClassName, 'Waiting all connections terminated');
    Sleep(100);
  end;
end;

end.

