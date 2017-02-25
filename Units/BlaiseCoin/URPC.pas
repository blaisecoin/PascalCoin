{
  Copyright (c) 2016 by Albert Molina
  Copyright (c) 2017 by BlaiseCoin developers

  Distributed under the MIT software license, see the accompanying file LICENSE
  or visit http://www.opensource.org/licenses/mit-license.php.

  This unit is a part of BlaiseCoin, a P2P crypto-currency.
}

unit URPC;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface

uses UThread, ULog, UConst, UNode, UAccounts, UCrypto, UBlockChain,
  UNetProtocol, UOpTransaction, UWalletKeys, UTime, UAES, UECIES,
  UJSONFunctions, classes, blcksock, synsock, IniFiles, Variants;

const
  CT_RPC_ErrNum_InternalError = 100;

  CT_RPC_ErrNum_MethodNotFound = 1001;
  CT_RPC_ErrNum_InvalidAccount = 1002;
  CT_RPC_ErrNum_InvalidBlock = 1003;
  CT_RPC_ErrNum_InvalidOperation = 1004;
  CT_RPC_ErrNum_InvalidPubKey = 1005;
  CT_RPC_ErrNum_NotFound = 1010;
  CT_RPC_ErrNum_WalletPasswordProtected = 1015;
  CT_RPC_ErrNum_InvalidData = 1016;

type

  { TRPCServer }

  TRPCServerThread = class;
  TRPCServer = class
  private
    FRPCServerThread : TRPCServerThread;
    FActive: Boolean;
    FWalletKeys: TWalletKeysExt;
    FPort: Word;
    FJSON20Strict: Boolean;
    FIniFileName: AnsiString;
    FIniFile : TIniFile;
    FRPCLog : TLog;
    FCallsCounter : Int64;
    FValidIPs: AnsiString;
    procedure SetActive(AValue: Boolean);
    procedure SetIniFileName(const Value: AnsiString);
    procedure SetLogFileName(const Value: AnsiString);
    function GetLogFileName : AnsiString;
    procedure SetValidIPs(const Value: AnsiString);  protected
    function IsValidClientIP(Const clientIp : String; clientPort : Word) : Boolean;
    procedure AddRPCLog(Const Sender : String; Const Message : String);
    function GetNewCallCounter : Int64;
  public
    constructor Create;
    destructor Destroy; override;
    property Port : Word read FPort Write FPort;
    property Active : Boolean read FActive write SetActive;
    property WalletKeys : TWalletKeysExt read FWalletKeys write FWalletKeys;
    //
    property JSON20Strict : Boolean read FJSON20Strict write FJSON20Strict;
    property IniFileName : AnsiString read FIniFileName write SetIniFileName;
    property LogFileName : AnsiString read GetLogFileName write SetLogFileName;
    property ValidIPs : AnsiString read FValidIPs write SetValidIPs;
  end;

  { TRPCServerThread }

  TRPCServerThread = class(TPCThread)
    FServerSocket:TTCPBlockSocket;
    FPort : Word;
  protected
    procedure BCExecute; override;
  public
    constructor Create(Port : Word);
    destructor Destroy; Override;
  end;

  { TRPCProcess }

  TRPCProcess = class(TPCThread)
  private
    FSock:TTCPBlockSocket;
    FNode : TNode;
  public
    constructor Create (hsock:tSocket);
    destructor Destroy; override;
    procedure BCExecute; override;
    function ProcessMethod(Const method : String; params : TPCJSONObject; jsonresponse : TPCJSONObject; var ErrorNum : Integer; var ErrorDesc : String) : Boolean;
  end;


implementation

uses  {$IFNDEF FPC}windows,{$ENDIF}
  SysUtils, Synautil;

var _RPCServer : TRPCServer = nil;

{ TRPCServer }

constructor TRPCServer.Create;
begin
  FActive := false;
  FRPCLog := nil;
  FIniFile := nil;
  FIniFileName := '';
  FJSON20Strict := true;
  FWalletKeys := nil;
  FRPCServerThread := nil;
  FPort := CT_JSONRPC_Port;
  FCallsCounter := 0;
  FValidIPs := '127.0.0.1;localhost'; // New Build 1.5 - By default, only localhost can access to RPC
  if not assigned(_RPCServer) then
    _RPCServer := Self;
end;

destructor TRPCServer.Destroy;
begin
  FreeAndNil(FRPCLog);
  active := false;
  if _RPCServer=Self then
    _RPCServer:= nil;
  inherited Destroy;
end;

procedure TRPCServer.AddRPCLog(Const Sender : String; Const Message : String);
begin
  if not Assigned(FRPCLog) then exit;
  FRPCLog.NotifyNewLog(ltinfo,Sender+' '+Inttostr(FCallsCounter),Message);
end;

function TRPCServer.GetLogFileName : AnsiString;
begin
  if Assigned(FRPCLog) then
    Result := FRPCLog.FileName
  else Result := '';
end;

function TRPCServer.GetNewCallCounter: Int64;
begin
  inc(FCallsCounter);
  Result := FCallsCounter;
end;

procedure TRPCServer.SetActive(AValue: Boolean);
begin
  if FActive=AValue then exit;
  FActive:=AValue;
  if (FActive) then
  begin
    FRPCServerThread := TRPCServerThread.Create(FPort);
  end
  else
  begin
    FRPCServerThread.Terminate;
    FRPCServerThread.WaitFor;
    FreeAndNil(FRPCServerThread);
  end;
  TLog.NewLog(ltupdate,Classname,'Updated RPC Server to Active='+CT_TRUE_FALSE[FActive]);
end;

procedure TRPCServer.SetIniFileName(const Value: AnsiString);
begin
  if FIniFileName=Value then
    exit;
  FreeAndNil(FIniFile);
  FIniFileName := Value;
  if (FIniFileName<>'') and (FileExists(FIniFileName)) then
  begin
    FIniFile := TIniFile.Create(FIniFileName);
  end;
  if Assigned(FIniFile) then
  begin
    FJSON20Strict := FIniFile.ReadBool('general','json20strict',true)
  end;
end;

procedure TRPCServer.SetLogFileName(const Value: AnsiString);
begin
  if (not Assigned(FRPCLog)) and (Trim(Value)<>'') then
  begin
    FRPCLog := TLog.Create(Nil);
    FRPCLog.ProcessGlobalLogs:=false;
    FRPCLog.SaveTypes:=CT_TLogTypes_ALL;
  end;
  if (trim(Value)<>'') then
  begin
    FRPCLog.FileName:=Value;
  end
  else
  FreeAndNil(FRPCLog);
end;

procedure TRPCServer.SetValidIPs(const Value: AnsiString);
begin
  if FValidIPs=Value then
    exit;
  FValidIPs := Value;
  if FValidIPs='' then
    TLog.NewLog(ltupdate,Classname,'Updated RPC Server valid IPs to ALL')
  else
    TLog.NewLog(ltupdate,Classname,'Updated RPC Server valid IPs to: '+FValidIPs)
end;

function TRPCServer.IsValidClientIP(const clientIp: String; clientPort: Word): Boolean;
begin
  if FValidIPs='' then
    Result := true
  else
  begin
    Result := pos(clientIP,FValidIPs) > 0;
  end;
end;

{ TRPCProcess }

constructor TRPCProcess.Create(hsock: tSocket);
begin
  FSock:=TTCPBlockSocket.create;
  FSock.socket:=HSock;
  FreeOnTerminate:=true;
  FNode := TNode.Node;
  //Priority:=tpNormal;
  inherited create(false);
  FreeOnTerminate:=true;
end;

destructor TRPCProcess.Destroy;
begin
  FSock.free;
  inherited Destroy;
end;

procedure TRPCProcess.BCExecute;
var
  timeout: integer;
  s: string;
  method, uri, protocol: string;
  size: integer;
  x, n: integer;
  resultcode: integer;
  inputdata : TBytes;
  js : TPCJSONData;
  jsonobj,jsonresponse : TPCJSONObject;
  errNum : Integer; errDesc : String;
  jsonrequesttxt,
  jsonresponsetxt, methodName, paramsTxt : AnsiString;
  valid : Boolean;
  i : Integer;
  Headers : TStringList;
  tc : Cardinal;
  callcounter : Int64;
begin
  callcounter := _RPCServer.GetNewCallCounter;
  tc := GetTickCount;
  methodName := '';
  paramsTxt := '';
  // IP Protection
  if (not _RPCServer.IsValidClientIP(FSock.GetRemoteSinIP,FSock.GetRemoteSinPort)) then
  begin
    TLog.NewLog(lterror,Classname,FSock.GetRemoteSinIP+':'+inttostr(FSock.GetRemoteSinPort)+' INVALID IP');
    _RPCServer.AddRPCLog(FSock.GetRemoteSinIP+':'+InttoStr(FSock.GetRemoteSinPort),' INVALID IP');
    exit;
  end;
  errNum := CT_RPC_ErrNum_InternalError;
  errDesc := 'No data';
  valid := false;
  SetLength(inputdata,0);
  Headers := TStringList.Create;
  jsonresponse := TPCJSONObject.Create;
  try
    timeout := 5000;
    resultcode:= 200;
    repeat
      //read request line
      s := Fsock.RecvString(timeout);
      if Fsock.lasterror <> 0 then
        exit;
      if s = '' then
        exit;
      method := fetch(s, ' ');
      if (s = '') or (method = '') then
        exit;
      uri := fetch(s, ' '); if uri = '' then
        exit;
      protocol := fetch(s, ' ');
      headers.Clear;
      size := -1;
      //read request headers
      if protocol <> '' then
      begin
        if pos('HTTP/1.1', protocol) <> 1 then
        begin
          errDesc := 'Invalid protocol '+protocol;
          exit;
        end;
        repeat
          s := Fsock.RecvString(Timeout);
          if Fsock.lasterror <> 0 then
            exit;
          if Pos('CONTENT-LENGTH:', Uppercase(s)) = 1 then
            Size := StrToIntDef(SeparateRight(s, ' '), -1);
        until s = '';
      end;
      //recv document...
      if size >= 0 then
      begin
        setLength(inputdata,size);
        x := FSock.RecvBufferEx(InputData, Size, Timeout);
        if Fsock.lasterror <> 0 then
          exit;
        if (x<>size) and (x>0) then
          setLength(inputdata,x);
      end
      else
        setlength(inputdata,0);
      SetLength(jsonrequesttxt,length(inputdata));
      for i:=0 to high(inputdata) do
      begin
        jsonrequesttxt[i+1] := AnsiChar(inputdata[i]);
      end;
      // Convert InputData to JSON object
      js := nil;
      try
        js := TPCJSONData.ParseJSONValue(jsonrequesttxt);
      except
        on E:Exception do
        begin
          errDesc:='Error decoding JSON: '+E.Message;
          TLog.NewLog(lterror,Classname,FSock.GetRemoteSinIP+':'+inttostr(FSock.GetRemoteSinPort)+' Error decoding JSON: '+E.Message);
          exit;
        end;
      end;
      if Assigned(js) then
      begin
        try
          if (js is TPCJSONObject) then
          begin
            jsonobj := TPCJSONObject(js);
            errNum := 0;
            errDesc := '';
            try
              methodName := jsonobj.AsString('method','');
              paramsTxt := jsonobj.GetAsObject('params').ToJSON(false);
              TLog.NewLog(ltinfo,Classname,FSock.GetRemoteSinIP+':'+inttostr(FSock.GetRemoteSinPort)+' Processing method '+jsonobj.AsString('method',''));
              Valid := ProcessMethod(jsonobj.AsString('method',''),jsonobj.GetAsObject('params'),jsonresponse,errNum,errDesc);
              if not Valid then
              begin
                if (errNum<>0) or (errDesc<>'') then
                begin
                  jsonresponse.GetAsObject('error').GetAsVariant('code').Value:=errNum;
                  jsonresponse.GetAsObject('error').GetAsVariant('message').Value:=errDesc;
                end else
                begin
                  jsonresponse.GetAsObject('error').GetAsVariant('code').Value:=CT_RPC_ErrNum_InternalError;
                  jsonresponse.GetAsObject('error').GetAsVariant('message').Value:='Unknown error processing method';
                end;
              end;
            except
              on E:Exception do
              begin
                TLog.NewLog(lterror,Classname,'Exception processing method'+jsonobj.AsString('method','')+' ('+E.ClassName+'): '+E.Message);
                jsonresponse.GetAsObject('error').GetAsVariant('code').Value:=CT_RPC_ErrNum_InternalError;
                jsonresponse.GetAsObject('error').GetAsVariant('message').Value:=E.Message;
                valid:=False;
              end;
            end;
            jsonresponse.GetAsVariant('id').Value:= jsonobj.GetAsVariant('id').Value;
            jsonresponse.GetAsVariant('jsonrpc').Value:= '2.0';
          end;
        finally
          js.free;
        end;
      end else
      begin
        TLog.NewLog(lterror,ClassName,FSock.GetRemoteSinIP+':'+inttostr(FSock.GetRemoteSinPort)+' Received data is not a JSON: '+jsonrequesttxt+' (length '+inttostr(length(jsonrequesttxt))+' bytes)');
      end;
    until (FSock.LastError <> 0) or (protocol<>'');
  finally
    try
      // Send result:
      if Fsock.lasterror = 0 then
      begin
        // Save JSON response:
        if (not Valid) then
        begin
          if not assigned(jsonresponse.FindName('error')) then
          begin
            jsonresponse.GetAsObject('error').GetAsVariant('code').Value:=errNum;
            jsonresponse.GetAsObject('error').GetAsVariant('message').Value:=errDesc;
          end;
        end;
        jsonresponsetxt := jsonresponse.ToJSON(false);
        Fsock.SendString(protocol + ' ' + IntTostr(ResultCode) + CRLF);
        if (protocol <> '') then
        begin
          headers.Add('Server: BlaiseCoin HTTP JSON-RPC Server');
          headers.Add('Content-Type: application/json;charset=utf-8');
          headers.Add('Content-length: ' + IntTostr(length(jsonresponsetxt)));
          headers.Add('Connection: close');
          headers.Add('Access-Control-Allow-Origin: *');
          headers.Add('Date: ' + Rfc822DateTime(now));
          headers.Add('');
          for n := 0 to headers.count - 1 do
            Fsock.sendstring(headers[n] + CRLF);
        end;
        if Fsock.lasterror = 0 then
        begin
          FSock.SendBuffer(addr(jsonresponsetxt[1]),Length(jsonresponsetxt));
        end;
      end;
      _RPCServer.AddRPCLog(FSock.GetRemoteSinIP+':'+InttoStr(FSock.GetRemoteSinPort),'Method:'+methodName+' Params:'+paramsTxt+' '+Inttostr(errNum)+':'+errDesc+' Time:'+FormatFloat('0.000',(GetTickCount - tc)/1000));
    finally
      jsonresponse.free;
      Headers.Free; // Memory leak on Build 1.3
    end;
  end;
end;

function TRPCProcess.ProcessMethod(const method: String; params: TPCJSONObject;
  jsonresponse: TPCJSONObject; var ErrorNum: Integer; var ErrorDesc: String): Boolean;

  var _ro : TPCJSONObject;
      _ra : TPCJSONArray;

  function GetResultObject : TPCJSONObject;
  begin
    if not assigned(_ro) then
    begin
      _ro := jsonresponse.GetAsObject('result');
      _ra := nil;
    end;
    Result := _ro;
  end;

  function GetResultArray : TPCJSONArray;
  begin
    if not assigned(_ra) then
    begin
      _ra := jsonresponse.GetAsArray('result');
      _ro := nil;
    end;
    Result := _ra;
  end;

  function ToJSONCurrency(pascalCoins : Int64) : Real;
  begin
    Result := pascalCoins / 10000;
  end;

  function ToPascalCoins(jsonCurr : Real) : Int64;
  begin
    Result := Round(jsonCurr * 10000);
  end;

  function HexaStringToOperationsHashTree(Const HexaStringOperationsHashTree : AnsiString; out OperationsHashTree : TOperationsHashTree; var errors : AnsiString) : Boolean;
  var raw : TRawBytes;
    ms : TMemoryStream;
  begin
    Result := False;
    raw := TCrypto.HexaToRaw(HexaStringOperationsHashTree);
    if (HexaStringOperationsHashTree<>'') and (raw='') then
    begin
      errors := 'Invalid HexaString as operations';
      exit;
    end;
    ms := TMemoryStream.Create;
    try
      ms.WriteBuffer(raw[1],length(raw));
      ms.Position := 0;
      OperationsHashTree := TOperationsHashTree.Create;
      if (raw<>'') then
      begin
        if not OperationsHashTree.LoadOperationsHashTreeFromStream(ms,false,errors) then
        begin
          FreeAndNil(OperationsHashTree);
          exit;
        end;
      end;
      Result := true;
    finally
      ms.Free;
    end;
  end;

  function OperationsHashTreeToHexaString(Const OperationsHashTree : TOperationsHashTree) : AnsiString;
  var ms : TMemoryStream;
    raw : TRawBytes;
  begin
    ms := TMemoryStream.Create;
    try
      OperationsHashTree.SaveOperationsHashTreeToStream(ms,false);
      ms.Position := 0;
      SetLength(raw,ms.Size);
      ms.ReadBuffer(raw[1],ms.Size);
      Result := TCrypto.ToHexaString(raw);
    finally
      ms.Free;
    end;
  end;

  function GetBlock(nBlock : Cardinal; jsonObject : TPCJSONObject) : Boolean;
  var pcops : TPCOperationsComp;
  begin
    pcops := TPCOperationsComp.Create(Nil);
    try
      if not FNode.Bank.LoadOperations(pcops,nBlock) then
      begin
        ErrorNum := CT_RPC_ErrNum_InternalError;
        ErrorDesc := 'Cannot load Block: '+IntToStr(nBlock);
        Result := False;
        exit;
      end;
      jsonObject.GetAsVariant('block').Value:=pcops.OperationBlock.block;
      jsonObject.GetAsVariant('enc_pubkey').Value := TCrypto.ToHexaString(TAccountComp.AccountKey2RawString(pcops.OperationBlock.account_key));
      jsonObject.GetAsVariant('reward').Value:=ToJSONCurrency(pcops.OperationBlock.reward);
      jsonObject.GetAsVariant('fee').Value:=ToJSONCurrency(pcops.OperationBlock.fee);
      jsonObject.GetAsVariant('ver').Value:=pcops.OperationBlock.protocol_version;
      jsonObject.GetAsVariant('ver_a').Value:=pcops.OperationBlock.protocol_available;
      jsonObject.GetAsVariant('timestamp').Value:=Int64(pcops.OperationBlock.timestamp);
      jsonObject.GetAsVariant('target').Value:=Int64(pcops.OperationBlock.compact_target);
      jsonObject.GetAsVariant('nonce').Value:=Int64(pcops.OperationBlock.nonce);
      jsonObject.GetAsVariant('payload').Value:=pcops.OperationBlock.block_payload;
      jsonObject.GetAsVariant('sbh').Value:=TCrypto.ToHexaString(pcops.OperationBlock.initial_safe_box_hash);
      jsonObject.GetAsVariant('oph').Value:=TCrypto.ToHexaString(pcops.OperationBlock.operations_hash);
      jsonObject.GetAsVariant('pow').Value:=TCrypto.ToHexaString(pcops.OperationBlock.proof_of_work);
      jsonObject.GetAsVariant('operations').Value:=pcops.Count;
      jsonObject.GetAsVariant('hashratekhs').Value := FNode.Bank.SafeBox.CalcBlockHashRateInKhs(pcops.OperationBlock.Block,50);
      jsonObject.GetAsVariant('maturation').Value := FNode.Bank.BlocksCount - pcops.OperationBlock.block - 1;
      Result := True;
    finally
      pcops.Free;
    end;
  end;

  procedure FillOperationResumeToJSONObject(Const OPR : TOperationResume; jsonObject : TPCJSONObject);
  begin
    if not OPR.valid then
    begin
      jsonObject.GetAsVariant('valid').Value := OPR.valid;
    end;
    if (OPR.errors<>'') and (not OPR.valid) then
    begin
      jsonObject.GetAsVariant('errors').Value := OPR.errors;
    end;
    if OPR.valid then
    begin
      jsonObject.GetAsVariant('block').Value:=OPR.Block;
      jsonObject.GetAsVariant('time').Value:=OPR.time;
      jsonObject.GetAsVariant('opblock').Value:=OPR.NOpInsideBlock;
      if (OPR.Block>0) and (OPR.Block<FNode.Bank.BlocksCount) then
        jsonObject.GetAsVariant('maturation').Value := FNode.Bank.BlocksCount - OPR.Block - 1
      else
        jsonObject.GetAsVariant('maturation').Value := null;
    end;
    jsonObject.GetAsVariant('optype').Value:=OPR.OpType;
    jsonObject.GetAsVariant('account').Value:=OPR.AffectedAccount;
    jsonObject.GetAsVariant('optxt').Value:=OPR.OperationTxt;
    jsonObject.GetAsVariant('amount').Value:=ToJSONCurrency(OPR.Amount);
    jsonObject.GetAsVariant('fee').Value:=ToJSONCurrency(OPR.Fee);
    if (OPR.Balance>=0) and (OPR.valid) then jsonObject.GetAsVariant('balance').Value:=ToJSONCurrency(OPR.Balance);
    jsonObject.GetAsVariant('payload').Value:=TCrypto.ToHexaString(OPR.OriginalPayload);
    if OPR.SenderAccount>=0 then
    begin
      jsonObject.GetAsVariant('sender_account').Value:=OPR.SenderAccount;
    end;
    if OPR.DestAccount>=0 then
    begin
      jsonObject.GetAsVariant('dest_account').Value:=OPR.DestAccount;
    end;
    if OPR.newKey.EC_OpenSSL_NID>0 then
    begin
      jsonObject.GetAsVariant('enc_pubkey').Value := TCrypto.ToHexaString(TAccountComp.AccountKey2RawString(OPR.newKey));
    end;
    if (OPR.valid) and (OPR.OperationHash<>'') then
    begin
      jsonObject.GetAsVariant('ophash').Value := TCrypto.ToHexaString(OPR.OperationHash);
    end;
  end;

  procedure FillOperationsHashTreeToJSONObject(Const OperationsHashTree : TOperationsHashTree; jsonObject : TPCJSONObject);
  begin
    jsonObject.GetAsVariant('operations').Value:=OperationsHashTree.OperationsCount;
    jsonObject.GetAsVariant('amount').Value:=ToJSONCurrency(OperationsHashTree.TotalAmount);
    jsonObject.GetAsVariant('fee').Value:=ToJSONCurrency(OperationsHashTree.TotalFee);
    jsonObject.GetAsVariant('rawoperations').Value:=OperationsHashTreeToHexaString(OperationsHashTree);
  end;

  function GetAccountOperations(AccountNumber : Cardinal; jsonArray : TPCJSONArray; MaxBlocksDepht,start,max : Integer) : Boolean;
  var
    list : TList;
    Op : TPCOperation;
    OPR : TOperationResume;
    Obj : TPCJSONObject;
    OperationsResume : TOperationsResumeList;
    i : Integer;
  begin
    OperationsResume := TOperationsResumeList.Create;
    try
      list := TList.Create;
      try
        FNode.Operations.OperationsHashTree.GetOperationsAffectingAccount(AccountNumber,list);
        for i := list.Count - 1 downto 0 do
        begin
          Op := FNode.Operations.OperationsHashTree.GetOperation(PtrInt(list[i]));
          if TPCOperation.OperationToOperationResume(0,Op,AccountNumber,OPR) then
          begin
            OPR.NOpInsideBlock := i;
            OPR.Block := FNode.Operations.OperationBlock.block;
            OPR.Balance := FNode.Operations.SafeBoxTransaction.Account(AccountNumber).balance;
            OperationsResume.Add(OPR);
          end;
        end;
      finally
        list.Free;
      end;
      if ((max<=0) or (OperationsResume.Count<(max+start))) then
      begin
        FNode.GetStoredOperationsFromAccount(OperationsResume,AccountNumber,MaxBlocksDepht,max+start);
      end;
      //
      for i:=0 to OperationsResume.Count-1 do
      begin
        if (i>=start) then
        begin
          Obj := jsonArray.GetAsObject(jsonArray.Count);
          OPR := OperationsResume[i];
          FillOperationResumeToJSONObject(OPR,Obj);
          if ((max>0) and (jsonArray.Count>=max)) then
            break; // stop
        end;
      end;
      Result := True;
    finally
      OperationsResume.Free;
    end;
  end;

  procedure GetConnections;
  var i : Integer;
    l : TList;
    nc : TNetConnection;
    obj: TPCJSONObject;
  begin
    l := TNetData.NetData.NetConnections.LockList;
    try
      for i:=0 to l.Count-1 do
      begin
        nc := TNetData.NetData.Connection(i);
        obj := jsonresponse.GetAsArray('result').GetAsObject(i);
        obj.GetAsVariant('server').Value := not (nc is TNetServerClient);
        obj.GetAsVariant('ip').Value:=nc.Client.RemoteHost;
        obj.GetAsVariant('port').Value:=nc.Client.RemotePort;
        obj.GetAsVariant('secs').Value:=UnivDateTimeToUnix(now) - UnivDateTimeToUnix(nc.CreatedTime);
        obj.GetAsVariant('sent').Value:=nc.Client.BytesSent;
        obj.GetAsVariant('recv').Value:=nc.Client.BytesReceived;
        obj.GetAsVariant('appver').Value:=nc.ClientAppVersion;
        obj.GetAsVariant('netver').Value:=nc.NetProtocolVersion.protocol_version;
        obj.GetAsVariant('netver_a').Value:=nc.NetProtocolVersion.protocol_available;
      end;
    finally
      TNetData.NetData.NetConnections.UnlockList;
    end;
  end;

  // This function creates a TOpTransaction without looking for balance/private key of sender account
  // It assumes that sender,target,sender_last_n_operation,senderAccountKey and targetAccountKey are correct
  function CreateOperationTransaction(sender, target, sender_last_n_operation : Cardinal; amount, fee : UInt64;
    Const senderAccounKey, targetAccountKey : TAccountKey; Const RawPayload : TRawBytes;
    Const Payload_method, EncodePwd : AnsiString) : TOpTransaction;
  // "payload_method" types: "none","dest"(default),"sender","aes"(must provide "pwd" param)
  var i : Integer;
    f_raw : TRawBytes;
  begin
    Result := nil;
    i := _RPCServer.FWalletKeys.IndexOfAccountKey(senderAccounKey);
    if i<0 then
    begin
      ErrorDesc:='Sender Public Key not found in wallet: '+TAccountComp.AccountKeyToExport(senderAccounKey);
      ErrorNum:=CT_RPC_ErrNum_InvalidPubKey;
      exit;
    end;
    if (not assigned(_RPCServer.FWalletKeys.Key[i].PrivateKey)) then
    begin
      if _RPCServer.FWalletKeys.Key[i].CryptedKey<>'' then
      begin
        // Wallet is password protected
        ErrorDesc := 'Wallet is password protected';
        ErrorNum := CT_RPC_ErrNum_WalletPasswordProtected;
      end else
      begin
        ErrorDesc := 'Wallet private key not found in Wallet';
        ErrorNum := CT_RPC_ErrNum_InvalidPubKey;
      end;
      exit;
    end;
    //
    if (length(RawPayload)>0) then
    begin
      if (Payload_method='none') then
        f_raw:=RawPayload
      else if (Payload_method='dest') then
      begin
        f_raw := ECIESEncrypt(targetAccountKey,RawPayload);
      end else if (Payload_method='sender') then
      begin
        f_raw := ECIESEncrypt(senderAccounKey,RawPayload);
      end else if (Payload_method='aes') then
      begin
        f_raw := TAESComp.EVP_Encrypt_AES256(RawPayload,EncodePwd);
      end else
      begin
        ErrorNum:=CT_RPC_ErrNum_InvalidOperation;
        ErrorDesc:='Invalid encode payload method: '+Payload_method;
        exit;
      end;
    end
    else
      f_raw := '';
    Result := TOpTransaction.Create(sender,sender_last_n_operation+1,target,_RPCServer.FWalletKeys.Key[i].PrivateKey,amount,fee,f_raw);
    if not Result.HasValidSignature then
    begin
      FreeAndNil(Result);
      ErrorNum:=CT_RPC_ErrNum_InternalError;
      ErrorDesc:='Invalid signature';
      exit;
    end;
  end;

  function OpSendTo(sender, target : Cardinal; amount, fee : UInt64; Const RawPayload : TRawBytes; Const Payload_method, EncodePwd : AnsiString) : Boolean;
  // "payload_method" types: "none","dest"(default),"sender","aes"(must provide "pwd" param)
  var
    opt : TOpTransaction;
    sacc,tacc : TAccount;
    errors : AnsiString;
    opr : TOperationResume;
  begin
    Result := false;
    if (sender<0) or (sender>=FNode.Bank.AccountsCount) then
    begin
      if (sender=CT_MaxAccount) then
        ErrorDesc := 'Need sender'
      else
        ErrorDesc:='Invalid sender account '+Inttostr(sender);
      ErrorNum:=CT_RPC_ErrNum_InvalidAccount;
      exit;
    end;
    if (target<0) or (target>=FNode.Bank.AccountsCount) then
    begin
      if (target=CT_MaxAccount) then
        ErrorDesc := 'Need target'
      else
        ErrorDesc:='Invalid target account '+Inttostr(target);
      ErrorNum:=CT_RPC_ErrNum_InvalidAccount;
      exit;
    end;
    sacc := FNode.Operations.SafeBoxTransaction.Account(sender);
    tacc := FNode.Operations.SafeBoxTransaction.Account(target);

    opt := CreateOperationTransaction(sender,target,sacc.n_operation,amount,fee,sacc.accountkey,tacc.accountkey,RawPayload,Payload_method,EncodePwd);
    if opt=nil then
      exit;
    try
      if not FNode.AddOperation(nil,opt,errors) then
      begin
        ErrorDesc := 'Error adding operation: '+errors;
        ErrorNum := CT_RPC_ErrNum_InvalidOperation;
        exit;
      end;
      TPCOperation.OperationToOperationResume(0,opt,sender,opr);
      FillOperationResumeToJSONObject(opr,GetResultObject);
      Result := true;
    finally
      opt.free;
    end;
  end;

  function SignOpSendTo(Const HexaStringOperationsHashTree : TRawBytes; sender, target : Cardinal;
    Const senderAccounKey, targetAccountKey : TAccountKey;
    last_sender_n_operation : Cardinal;
    amount, fee : UInt64; Const RawPayload : TRawBytes; Const Payload_method, EncodePwd : AnsiString) : Boolean;
  // "payload_method" types: "none","dest"(default),"sender","aes"(must provide "pwd" param)
  var
    OperationsHashTree : TOperationsHashTree;
    errors : AnsiString;
    opt : TOpTransaction;
  begin
    Result := false;
    if not HexaStringToOperationsHashTree(HexaStringOperationsHashTree,OperationsHashTree,errors) then
    begin
      ErrorNum:=CT_RPC_ErrNum_InvalidData;
      ErrorDesc:= 'Error decoding param "rawoperations": '+errors;
      exit;
    end;
    try
      opt := CreateOperationTransaction(sender,target,last_sender_n_operation,amount,fee,senderAccounKey,targetAccountKey,RawPayload,Payload_method,EncodePwd);
      if opt=nil then
        exit;
      try
        OperationsHashTree.AddOperationToHashTree(opt);
        FillOperationsHashTreeToJSONObject(OperationsHashTree,GetResultObject);
        Result := true;
      finally
        opt.Free;
      end;
    finally
      OperationsHashTree.Free;
    end;
  end;

  // This function creates a TOpChangeKey without looking for private key of account
  // It assumes that account_number,account_last_n_operation and account_pubkey are correct
  function CreateOperationChangeKey(account_number, account_last_n_operation : Cardinal; const account_pubkey, new_pubkey : TAccountKey; fee : UInt64; RawPayload : TRawBytes; Const Payload_method, EncodePwd : AnsiString) : TOpChangeKey;
  // "payload_method" types: "none","dest"(default),"sender","aes"(must provide "pwd" param)
  var i : Integer;
    f_raw : TRawBytes;
  begin
    Result := nil;
    i := _RPCServer.FWalletKeys.IndexOfAccountKey(account_pubkey);
    if (i<0) then
    begin
      ErrorDesc:='Private key not found in wallet: '+TAccountComp.AccountKeyToExport(account_pubkey);
      ErrorNum:=CT_RPC_ErrNum_InvalidPubKey;
      exit;
    end;
    if (not assigned(_RPCServer.FWalletKeys.Key[i].PrivateKey)) then
    begin
      if _RPCServer.FWalletKeys.Key[i].CryptedKey<>'' then
      begin
        // Wallet is password protected
        ErrorDesc := 'Wallet is password protected';
        ErrorNum := CT_RPC_ErrNum_WalletPasswordProtected;
      end else
      begin
        ErrorDesc := 'Wallet private key not found in Wallet';
        ErrorNum := CT_RPC_ErrNum_InvalidAccount;
      end;
      exit;
    end;
    if (length(RawPayload)>0) then
    begin
      if (Payload_method='none') then
        f_raw:=RawPayload
      else if (Payload_method='dest') then
      begin
        f_raw := ECIESEncrypt(new_pubkey,RawPayload);
      end else if (Payload_method='sender') then
      begin
        f_raw := ECIESEncrypt(account_pubkey,RawPayload);
      end else if (Payload_method='aes') then
      begin
        f_raw := TAESComp.EVP_Encrypt_AES256(RawPayload,EncodePwd);
      end else
      begin
        ErrorNum:=CT_RPC_ErrNum_InvalidOperation;
        ErrorDesc:='Invalid encode payload method: '+Payload_method;
        exit;
      end;
    end
    else
      f_raw := '';
    Result := TOpChangeKey.Create(account_number,account_last_n_operation+1,_RPCServer.FWalletKeys.Key[i].PrivateKey,new_pubkey,fee,f_raw);
    if not Result.HasValidSignature then
    begin
      FreeAndNil(Result);
      ErrorNum:=CT_RPC_ErrNum_InternalError;
      ErrorDesc:='Invalid signature';
      exit;
    end;
  end;

  function ChangeAccountKey(account_number : Cardinal; const new_pub_key : TAccountKey; fee : UInt64; const RawPayload : TRawBytes; Const Payload_method, EncodePwd : AnsiString) : Boolean;
  // "payload_method" types: "none","dest"(default),"sender","aes"(must provide "pwd" param)
  var
    opck : TOpChangeKey;
    acc : TAccount;
    errors : AnsiString;
    opr : TOperationResume;
  begin
    Result := false;
    if (account_number<0) or (account_number>=FNode.Bank.AccountsCount) then
    begin
      ErrorDesc:='Invalid account '+Inttostr(account_number);
      ErrorNum:=CT_RPC_ErrNum_InvalidAccount;
      exit;
    end;
    acc := FNode.Operations.SafeBoxTransaction.Account(account_number);

    opck := CreateOperationChangeKey(account_number,acc.n_operation,acc.accountkey,new_pub_key,fee,RawPayload,Payload_method,EncodePwd);
    if not assigned(opck) then
      exit;
    try
      if not FNode.AddOperation(nil,opck,errors) then
      begin
        ErrorDesc := 'Error adding operation: '+errors;
        ErrorNum := CT_RPC_ErrNum_InvalidOperation;
        exit;
      end;
      TPCOperation.OperationToOperationResume(0,opck,account_number,opr);
      FillOperationResumeToJSONObject(opr,GetResultObject);
      Result := true;
    finally
      opck.free;
    end;
  end;

  function GetCardinalsValues(ordinals_coma_separated : String; cardinals : TOrderedCardinalList; var errors : AnsiString) : Boolean;
  var
    i,istart : Integer;
    ctxt : String;
    an : Cardinal;
  begin
    result := false;
    cardinals.Clear;
    errors := '';
    ctxt := '';
    istart := 1;
    for i := 1 to length(ordinals_coma_separated) do
    begin
      case ordinals_coma_separated[i] of
        '0'..'9','-' : ctxt := ctxt + ordinals_coma_separated[i];
        ',',';' :
        begin
          if trim(ctxt)<>'' then
          begin
            if not TAccountComp.AccountTxtNumberToAccountNumber(trim(ctxt),an) then
            begin
              errors := 'Invalid account number at pos '+IntToStr(istart)+': '+ctxt;
              exit;
            end;
            cardinals.Add(an);
          end;
          ctxt := '';
          istart := i+1;
        end;
        ' ' : ; // Continue...
      else
        errors := 'Invalid char at pos '+inttostr(i)+': "'+ordinals_coma_separated[i]+'"';
        exit;
      end;
    end;
    //
    if (trim(ctxt)<>'') then
    begin
      if not TAccountComp.AccountTxtNumberToAccountNumber(trim(ctxt),an) then
      begin
        errors := 'Invalid account number at pos '+IntToStr(istart)+': '+ctxt;
        exit;
      end;
      cardinals.Add(an);
    end;
    if cardinals.Count=0 then
    begin
      errors := 'No valid value';
      exit;
    end;
    Result := true;
  end;

  function ChangeAccountsKey(accounts_txt : String; const new_pub_key : TAccountKey; fee : UInt64; const RawPayload : TRawBytes; Const Payload_method, EncodePwd : AnsiString) : Boolean;
  // "payload_method" types: "none","dest"(default),"sender","aes"(must provide "pwd" param)
  var
    opck : TOpChangeKey;
    acc : TAccount;
    i, ian : Integer;
    errors : AnsiString;
    accountsnumber : TOrderedCardinalList;
    operationsht : TOperationsHashTree;
    OperationsResumeList : TOperationsResumeList;
  begin
    Result := false;
    accountsnumber := TOrderedCardinalList.Create;
    try
      if not GetCardinalsValues(accounts_txt,accountsnumber,errors) then
      begin
        ErrorDesc := 'Error in accounts: '+errors;
        ErrorNum := CT_RPC_ErrNum_InvalidAccount;
        exit;
      end;
      operationsht := TOperationsHashTree.Create;
      try
        for ian := 0 to accountsnumber.Count - 1 do
        begin
          if (accountsnumber.Get(ian)<0) or (accountsnumber.Get(ian)>=FNode.Bank.AccountsCount) then
          begin
            ErrorDesc:='Invalid account '+Inttostr(accountsnumber.Get(ian));
            ErrorNum:=CT_RPC_ErrNum_InvalidAccount;
            exit;
          end;
          acc := FNode.Operations.SafeBoxTransaction.Account(accountsnumber.Get(ian));
          opck := CreateOperationChangeKey(acc.account,acc.n_operation,acc.accountkey,new_pub_key,fee,RawPayload,Payload_method,EncodePwd);
          if not assigned(opck) then
            exit;
          try
            operationsht.AddOperationToHashTree(opck);
          finally
            opck.free;
          end;
        end; // For
        // Ready to execute...
        OperationsResumeList := TOperationsResumeList.Create;
        try
          i := FNode.AddOperations(nil,operationsht,OperationsResumeList, errors);
          if (i<0) then
          begin
            ErrorNum:=CT_RPC_ErrNum_InternalError;
            ErrorDesc:=errors;
            exit;
          end;
          GetResultArray.Clear; // Inits an array
          for i := 0 to OperationsResumeList.Count - 1 do
          begin
            FillOperationResumeToJSONObject(OperationsResumeList[i],GetResultArray.GetAsObject(i));
          end;
        finally
          OperationsResumeList.Free;
        end;
        Result := true;
      finally
        operationsht.Free;
      end;
    finally
      accountsnumber.Free;
    end;
  end;

  function SignOpChangeKey(Const HexaStringOperationsHashTree : TRawBytes; account : Cardinal;
    Const actualAccounKey, newAccountKey : TAccountKey;
    last_n_operation : Cardinal;
    fee : UInt64; Const RawPayload : TRawBytes; Const Payload_method, EncodePwd : AnsiString) : Boolean;
  // "payload_method" types: "none","dest"(default),"sender","aes"(must provide "pwd" param)
  var OperationsHashTree : TOperationsHashTree;
    errors : AnsiString;
    opck : TOpChangeKey;
  begin
    Result := false;
    if not HexaStringToOperationsHashTree(HexaStringOperationsHashTree,OperationsHashTree,errors) then
    begin
      ErrorNum:=CT_RPC_ErrNum_InvalidData;
      ErrorDesc:= 'Error decoding param "rawoperations": '+errors;
      exit;
    end;
    try
      opck := CreateOperationChangeKey(account,last_n_operation,actualAccounKey,newAccountKey,fee,RawPayload,Payload_method,EncodePwd);
      if opck=nil then
        exit;
      try
        OperationsHashTree.AddOperationToHashTree(opck);
        FillOperationsHashTreeToJSONObject(OperationsHashTree,GetResultObject);
        Result := true;
      finally
        opck.Free;
      end;
    finally
      OperationsHashTree.Free;
    end;
  end;

  function OperationsInfo(Const HexaStringOperationsHashTree : TRawBytes; jsonArray : TPCJSONArray) : Boolean;
  var
    OperationsHashTree : TOperationsHashTree;
    errors : AnsiString;
    OPR : TOperationResume;
    Obj : TPCJSONObject;
    Op : TPCOperation;
    i : Integer;
  begin
    if not HexaStringToOperationsHashTree(HexaStringOperationsHashTree,OperationsHashTree,errors) then
    begin
      ErrorNum:=CT_RPC_ErrNum_InvalidData;
      ErrorDesc:= 'Error decoding param "rawoperations": '+errors;
      exit;
    end;
    try
      jsonArray.Clear;
      for i := 0 to OperationsHashTree.OperationsCount - 1 do
      begin
        Op := OperationsHashTree.GetOperation(i);
        Obj := jsonArray.GetAsObject(i);
        if TPCOperation.OperationToOperationResume(0,Op,Op.SenderAccount,OPR) then
        begin
          OPR.NOpInsideBlock := i;
          OPR.Balance := -1;
        end
        else
          OPR := CT_TOperationResume_NUL;
        FillOperationResumeToJSONObject(OPR,Obj);
      end;
      Result := true;
    finally
      OperationsHashTree.Free;
    end;
  end;

  function ExecuteOperations(Const HexaStringOperationsHashTree : TRawBytes) : Boolean;
  var
    OperationsHashTree : TOperationsHashTree;
    errors : AnsiString;
    i : Integer;
    OperationsResumeList : TOperationsResumeList;
  begin
    if not HexaStringToOperationsHashTree(HexaStringOperationsHashTree,OperationsHashTree,errors) then
    begin
      ErrorNum:=CT_RPC_ErrNum_InvalidData;
      ErrorDesc:= 'Error decoding param "rawoperations": '+errors;
      exit;
    end;
    try
      errors := '';
      OperationsResumeList := TOperationsResumeList.Create;
      try
        i := FNode.AddOperations(nil,OperationsHashTree,OperationsResumeList,errors);
        if (i<0) then
        begin
          ErrorNum:=CT_RPC_ErrNum_InternalError;
          ErrorDesc:=errors;
          exit;
        end;
        GetResultArray.Clear; // Inits an array
        for i := 0 to OperationsResumeList.Count - 1 do
        begin
          FillOperationResumeToJSONObject(OperationsResumeList[i],GetResultArray.GetAsObject(i));
        end;
      finally
        OperationsResumeList.Free;
      end;
      Result := true;
    finally
      OperationsHashTree.Free;
    end;
  end;

  procedure FillAccountObject(Const account : TAccount; jsonObj : TPCJSONObject);
  begin
    jsonObj.GetAsVariant('account').Value:=account.account;
    jsonObj.GetAsVariant('enc_pubkey').Value := TCrypto.ToHexaString(TAccountComp.AccountKey2RawString(account.accountkey));
    jsonObj.GetAsVariant('balance').Value:=ToJSONCurrency(account.balance);
    jsonObj.GetAsVariant('n_operation').Value:=account.n_operation;
    jsonObj.GetAsVariant('updated_b').Value:=account.updated_block;
  end;

  procedure FillPublicKeyObject(const PubKey : TAccountKey; jsonObj : TPCJSONObject);
  begin
    jsonObj.GetAsVariant('ec_nid').Value := PubKey.EC_OpenSSL_NID;
    jsonObj.GetAsVariant('x').Value := TCrypto.ToHexaString(PubKey.x);
    jsonObj.GetAsVariant('y').Value := TCrypto.ToHexaString(PubKey.y);
    jsonObj.GetAsVariant('enc_pubkey').Value := TCrypto.ToHexaString(TAccountComp.AccountKey2RawString(PubKey));
    jsonObj.GetAsVariant('b58_pubkey').Value := TAccountComp.AccountPublicKeyExport(PubKey);
  end;

  function DoEncrypt(RawPayload : TRawBytes; pub_key : TAccountKey; Const Payload_method, EncodePwd : AnsiString) : Boolean;
  var f_raw : TRawBytes;
  begin
    Result := false;
    if (length(RawPayload)>0) then
    begin
      if (Payload_method='none') then
        f_raw:=RawPayload
      else if (Payload_method='pubkey') then
      begin
        f_raw := ECIESEncrypt(pub_key,RawPayload);
      end else if (Payload_method='aes') then
      begin
        f_raw := TAESComp.EVP_Encrypt_AES256(RawPayload,EncodePwd);
      end else
      begin
        ErrorNum:=CT_RPC_ErrNum_InvalidOperation;
        ErrorDesc:='Invalid encode payload method: '+Payload_method;
        exit;
      end;
    end
    else
      f_raw := '';
    jsonresponse.GetAsVariant('result').Value := TCrypto.ToHexaString(f_raw);
    Result := true;
  end;

  function DoDecrypt(RawEncryptedPayload : TRawBytes; jsonArrayPwds : TPCJSONArray) : Boolean;
  var
    i : Integer;
    pkey : TECPrivateKey;
    decrypted_payload : TRawBytes;
  begin
    Result := false;
    if RawEncryptedPayload='' then
    begin
      GetResultObject.GetAsVariant('result').Value:= False;
      GetResultObject.GetAsVariant('enc_payload').Value:= '';
      // "payload_method" types: "none","dest"(default),"sender","aes"(must provide "pwd" param)
      Result := true;
      exit;
    end;
    for i := 0 to _RPCServer.WalletKeys.Count - 1 do
    begin
      pkey := _RPCServer.WalletKeys.Key[i].PrivateKey;
      if (assigned(pkey)) then
      begin
        if ECIESDecrypt(pkey.EC_OpenSSL_NID,pkey.PrivateKey,false,RawEncryptedPayload,decrypted_payload) then
        begin
          GetResultObject.GetAsVariant('result').Value:= true;
          GetResultObject.GetAsVariant('enc_payload').Value:= TCrypto.ToHexaString(RawEncryptedPayload);
          GetResultObject.GetAsVariant('unenc_payload').Value:= decrypted_payload;
          GetResultObject.GetAsVariant('payload_method').Value:= 'key';
          GetResultObject.GetAsVariant('enc_pubkey').Value:= TCrypto.ToHexaString(TAccountComp.AccountKey2RawString(pkey.PublicKey));
          // "payload_method" types: "none","dest"(default),"sender","aes"(must provide "pwd" param)
          Result := true;
          exit;
        end;
      end;
    end;
    for i := 0 to jsonArrayPwds.Count - 1 do
    begin
      if TAESComp.EVP_Decrypt_AES256(RawEncryptedPayload,jsonArrayPwds.GetAsVariant(i).AsString(''),decrypted_payload) then
      begin
        GetResultObject.GetAsVariant('result').Value:= true;
        GetResultObject.GetAsVariant('enc_payload').Value:= TCrypto.ToHexaString(RawEncryptedPayload);
        GetResultObject.GetAsVariant('unenc_payload').Value:= decrypted_payload;
        GetResultObject.GetAsVariant('payload_method').Value:= 'pwd';
        GetResultObject.GetAsVariant('pwd').Value:= jsonArrayPwds.GetAsVariant(i).AsString('');
        // "payload_method" types: "none","dest"(default),"sender","aes"(must provide "pwd" param)
        Result := true;
        exit;
      end;
    end;
    // not found
    GetResultObject.GetAsVariant('result').Value:= False;
    GetResultObject.GetAsVariant('enc_payload').Value:= TCrypto.ToHexaString(RawEncryptedPayload);
    Result := true;
  end;

  function CapturePubKey(const prefix : String; var pubkey : TAccountKey; var errortxt : String) : Boolean;
  var
    ansistr : AnsiString;
    auxpubkey : TAccountKey;
  begin
    pubkey := CT_Account_NUL.accountkey;
    errortxt := '';
    Result := false;
    if (params.IndexOfName(prefix+'b58_pubkey')>=0) then
    begin
      if not TAccountComp.AccountPublicKeyImport(params.AsString(prefix+'b58_pubkey',''),pubkey,ansistr) then
      begin
        errortxt:= 'Invalid value of param "'+prefix+'b58_pubkey": '+ansistr;
        exit;
      end;
      if (params.IndexOfName(prefix+'enc_pubkey')>=0) then
      begin
        auxpubkey := TAccountComp.RawString2Accountkey(TCrypto.HexaToRaw(params.AsString(prefix+'enc_pubkey','')));
        if (not TAccountComp.Equal(auxpubkey,pubkey)) then
        begin
          errortxt := 'Params "'+prefix+'b58_pubkey" and "'+prefix+'enc_pubkey" public keys are not the same public key';
          exit;
        end;
      end;
    end else
    begin
      if (params.IndexOfName(prefix+'enc_pubkey')<0) then
      begin
        errortxt := 'Need param "'+prefix+'enc_pubkey" or "'+prefix+'b58_pubkey"';
        exit;
      end;
      pubkey := TAccountComp.RawString2Accountkey(TCrypto.HexaToRaw(params.AsString(prefix+'enc_pubkey','')));
    end;
    if not TAccountComp.IsValidAccountKey(pubkey,ansistr) then
    begin
      errortxt := 'Invalid public key: '+ansistr;
    end
    else
      Result := true;
  end;

var
  c,c2 : Cardinal;
  i,j,k,l : Integer;
  account : TAccount;
  senderpubkey,destpubkey : TAccountKey;
  ansistr : AnsiString;
  nsaarr : TNodeServerAddressArray;
  pcops : TPCOperationsComp;
  ecpkey : TECPrivateKey;
  opr : TOperationResume;
  r : TRawBytes;
  ocl : TOrderedCardinalList;
  jsonarr : TPCJSONArray;
  jso : TPCJSONObject;
begin
  _ro := nil;
  _ra := nil;
  ErrorNum:=0;
  ErrorDesc:='';
  Result := false;
  TLog.NewLog(ltdebug,ClassName,'Processing RPC-JSON method '+method);
  if (method='addnode') then
  begin
    // Param "nodes" contains ip's and ports in format "ip1:port1;ip2:port2 ...". if port is not specified, use default
    // Returns quantity of nodes added
    TNode.DecodeIpStringToNodeServerAddressArray(params.AsString('nodes',''),nsaarr);
    for i:=low(nsaarr) to high(nsaarr) do
    begin
      TNetData.NetData.AddServer(nsaarr[i]);
    end;
    jsonresponse.GetAsVariant('result').Value:=length(nsaarr);
    Result := true;
  end else if (method='getaccount') then
  begin
    // Param "account" contains account number
    // Returns JSON Object with account information based on BlockChain + Pending operations
    c := params.GetAsVariant('account').AsCardinal(CT_MaxAccount);
    if (c>=0) and (c<FNode.Bank.AccountsCount) then
    begin
      account := FNode.Operations.SafeBoxTransaction.Account(c);
      FillAccountObject(account,GetResultObject);
      Result := True;
    end else
    begin
      ErrorNum := CT_RPC_ErrNum_InvalidAccount;
      if (c=CT_MaxAccount) then
        ErrorDesc := 'Need "account" param'
      else
        ErrorDesc := 'Account not found: '+IntToStr(c);
    end;
  end else if (method='getwalletaccounts') then
  begin
    // Returns JSON array with accounts in Wallet
    jsonarr := jsonresponse.GetAsArray('result');
    if (params.IndexOfName('enc_pubkey')>=0) or (params.IndexOfName('b58_pubkey')>=0) then
    begin
      if not (CapturePubKey('',opr.newKey,ErrorDesc)) then
      begin
        ErrorNum := CT_RPC_ErrNum_InvalidPubKey;
        exit;
      end;
      i := _RPCServer.WalletKeys.AccountsKeyList.IndexOfAccountKey(opr.newKey);
      if (i<0) then
      begin
        ErrorNum := CT_RPC_ErrNum_NotFound;
        ErrorDesc := 'Public key not found in wallet';
        exit;
      end;
      ocl := _RPCServer.WalletKeys.AccountsKeyList.AccountKeyList[i];
      k := params.AsInteger('max',100);
      l := params.AsInteger('start',0);
      for j := 0 to ocl.Count - 1 do
      begin
        if (j>=l) then
        begin
          account := FNode.Operations.SafeBoxTransaction.Account(ocl.Get(j));
          FillAccountObject(account,jsonarr.GetAsObject(jsonarr.Count));
        end;
        if (k>0) and ((j+1)>=(k+l)) then
          break;
      end;
      Result := true;
    end else
    begin
      k := params.AsInteger('max',100);
      l := params.AsInteger('start',0);
      c := 0;
      for i:=0 to _RPCServer.WalletKeys.AccountsKeyList.Count-1 do
      begin
        ocl := _RPCServer.WalletKeys.AccountsKeyList.AccountKeyList[i];
        for j := 0 to ocl.Count - 1 do
        begin
          if (c>=l) then
          begin
            account := FNode.Operations.SafeBoxTransaction.Account(ocl.Get(j));
            FillAccountObject(account,jsonarr.GetAsObject(jsonarr.Count));
          end;
          inc(c);
          if (k>0) and (c>=(k+l)) then
            break;
        end;
        if (k>0) and (c>=(k+l)) then
          break;
      end;
      Result := true;
    end;
  end else if (method='getwalletaccountscount') then
  begin
    // New Build 1.1.1
    // Returns a number with count value
    if (params.IndexOfName('enc_pubkey')>=0) or (params.IndexOfName('b58_pubkey')>=0) then
    begin
      if not (CapturePubKey('',opr.newKey,ErrorDesc)) then
      begin
        ErrorNum := CT_RPC_ErrNum_InvalidPubKey;
        exit;
      end;
      i := _RPCServer.WalletKeys.AccountsKeyList.IndexOfAccountKey(opr.newKey);
      if (i<0) then
      begin
        ErrorNum := CT_RPC_ErrNum_NotFound;
        ErrorDesc := 'Public key not found in wallet';
        exit;
      end;
      ocl := _RPCServer.WalletKeys.AccountsKeyList.AccountKeyList[i];
      jsonresponse.GetAsVariant('result').value := ocl.count;
      Result := true;
    end else
    begin
      ErrorDesc := '';
      c :=0;
      for i:=0 to _RPCServer.WalletKeys.AccountsKeyList.Count-1 do
      begin
        ocl := _RPCServer.WalletKeys.AccountsKeyList.AccountKeyList[i];
        inc(c,ocl.count);
      end;
      jsonresponse.GetAsVariant('result').value := c;
      Result := true;
    end;
  end else if (method='getwalletcoins') then
  begin
    if (params.IndexOfName('enc_pubkey')>=0) or (params.IndexOfName('b58_pubkey')>=0) then
    begin
      if not (CapturePubKey('',opr.newKey,ErrorDesc)) then
      begin
        ErrorNum := CT_RPC_ErrNum_InvalidPubKey;
        exit;
      end;
      i := _RPCServer.WalletKeys.AccountsKeyList.IndexOfAccountKey(opr.newKey);
      if (i<0) then
      begin
        ErrorNum := CT_RPC_ErrNum_NotFound;
        ErrorDesc := 'Public key not found in wallet';
        exit;
      end;
      ocl := _RPCServer.WalletKeys.AccountsKeyList.AccountKeyList[i];
      account.balance := 0;
      for j := 0 to ocl.Count - 1 do
      begin
        inc(account.balance, FNode.Operations.SafeBoxTransaction.Account(ocl.Get(j)).balance );
      end;
      jsonresponse.GetAsVariant('result').value := ToJSONCurrency(account.balance);
      Result := true;
    end else
    begin
      ErrorDesc := '';
      c :=0;
      account.balance := 0;
      for i:=0 to _RPCServer.WalletKeys.AccountsKeyList.Count-1 do
      begin
        ocl := _RPCServer.WalletKeys.AccountsKeyList.AccountKeyList[i];
        for j := 0 to ocl.Count - 1 do
        begin
          inc(account.balance, FNode.Operations.SafeBoxTransaction.Account(ocl.Get(j)).balance );
        end;
      end;
      jsonresponse.GetAsVariant('result').value := ToJSONCurrency(account.balance);
      Result := true;
    end;
  end else if (method='getwalletpubkeys') then
  begin
    // Returns JSON array with pubkeys in wallet
    k := params.AsInteger('max',100);
    j := params.AsInteger('start',0);
    jsonarr := jsonresponse.GetAsArray('result');
    for i:=0 to _RPCServer.WalletKeys.Count-1 do
    begin
      if (i>=j) then
      begin
        jso := jsonarr.GetAsObject(jsonarr.count);
        jso.GetAsVariant('name').Value := _RPCServer.WalletKeys.Key[i].Name;
        jso.GetAsVariant('can_use').Value := (_RPCServer.WalletKeys.Key[i].CryptedKey<>'');
        FillPublicKeyObject(_RPCServer.WalletKeys.Key[i].AccountKey,jso);
      end;
      if (k>0) and ((i+1)>=(j+k)) then
        break;
    end;
    Result := true;
  end else if (method='getwalletpubkey') then
  begin
    if not (CapturePubKey('',opr.newKey,ErrorDesc)) then
    begin
      ErrorNum := CT_RPC_ErrNum_InvalidPubKey;
      exit;
    end;
    i := _RPCServer.WalletKeys.AccountsKeyList.IndexOfAccountKey(opr.newKey);
    if (i<0) then
    begin
      ErrorNum := CT_RPC_ErrNum_NotFound;
      ErrorDesc := 'Public key not found in wallet';
      exit;
    end;
    FillPublicKeyObject(_RPCServer.WalletKeys.AccountsKeyList.AccountKey[i],GetResultObject);
    Result := true;
  end else if (method='getblock') then
  begin
    // Param "block" contains block number (0..getblockcount-1)
    // Returns JSON object with block information
    c := params.GetAsVariant('block').AsCardinal(CT_MaxBlock);
    if (c>=0) and (c<FNode.Bank.BlocksCount) then
    begin
      Result := GetBlock(c,GetResultObject);
    end else
    begin
      ErrorNum := CT_RPC_ErrNum_InvalidBlock;
      if (c=CT_MaxBlock) then ErrorDesc := 'Need block param'
      else ErrorDesc := 'Block not found: '+IntToStr(c);
    end;
  end else if (method='getblocks') then
  begin
    // Param "start" "end" contains blocks number (0..getblockcount-1)
    // Returns JSON array with blocks information (limited to 1000 blocks)
    // Sorted by DESCENDING blocknumber
    i := params.AsCardinal('last',0);
    if (i>0) then begin
      if (i>1000) then i := 1000;
      c2 := FNode.Bank.BlocksCount-1;
      if (FNode.Bank.BlocksCount>=i) then
        c := (FNode.Bank.BlocksCount) - i
      else
        c := 0;
    end else
    begin
      c := params.GetAsVariant('start').AsCardinal(CT_MaxBlock);
      c2 := params.GetAsVariant('end').AsCardinal(CT_MaxBlock);
      i := params.AsInteger('max',0);
      if (c<FNode.Bank.BlocksCount) and (i>0) and (i<=1000) then
      begin
        if (c+i<FNode.Bank.BlocksCount) then
          c2 := c+i
        else
          c2 := FNode.Bank.BlocksCount-1;
      end;
    end;
    if ((c>=0) and (c<FNode.Bank.BlocksCount)) and (c2>=c) and (c2<FNode.Bank.BlocksCount) then
    begin
      i := 0; Result := true;
      while (c<=c2) and (Result) and (i<1000) do
      begin
        Result := GetBlock(c2,jsonresponse.GetAsArray('result').GetAsObject(i));
        dec(c2); inc(i);
      end;
    end else
    begin
      ErrorNum := CT_RPC_ErrNum_InvalidBlock;
      if (c>c2) then
        ErrorDesc := 'Block start > block end'
      else if (c=CT_MaxBlock) or (c2=CT_MaxBlock) then
        ErrorDesc:='Need param "last" or "start" and "end"/"max"'
      else if (c2>=FNode.Bank.BlocksCount) then
        ErrorDesc := 'Block higher or equal to getblockccount: '+IntToStr(c2)
      else
        ErrorDesc := 'Block not found: '+IntToStr(c);
    end;
  end else if (method='getblockcount') then
  begin
    // Returns a number with Node blocks count
    jsonresponse.GetAsVariant('result').Value:=FNode.Bank.BlocksCount;
    Result := True;
  end else if (method='getblockoperation') then
  begin
    // Param "block" contains block. Null = Pending operation
    // Param "opblock" contains operation inside a block: (0..getblock.operations-1)
    // Returns a JSON object with operation values as "Operation resume format"
    c := params.GetAsVariant('block').AsCardinal(CT_MaxBlock);
    if (c>=0) and (c<FNode.Bank.BlocksCount) then
    begin
      pcops := TPCOperationsComp.Create(Nil);
      try
        if not FNode.Bank.LoadOperations(pcops,c) then
        begin
          ErrorNum := CT_RPC_ErrNum_InternalError;
          ErrorDesc := 'Cannot load Block: '+IntToStr(c);
          exit;
        end;
        i := params.GetAsVariant('opblock').AsInteger(0);
        if (i<0) or (i>=pcops.Count) then
        begin
          ErrorNum := CT_RPC_ErrNum_InvalidOperation;
          ErrorDesc := 'Block/Operation not found: '+IntToStr(c)+'/'+IntToStr(i)+' BlockOperations:'+IntToStr(pcops.Count);
          exit;
        end;
        if TPCOperation.OperationToOperationResume(c,pcops.Operation[i],pcops.Operation[i].SenderAccount,opr) then
        begin
          opr.NOpInsideBlock:=i;
          opr.time:=pcops.OperationBlock.timestamp;
          opr.Balance := -1;
          FillOperationResumeToJSONObject(opr,GetResultObject);
        end;
        Result := True;
      finally
        pcops.Free;
      end;
    end else
    begin
      if (c=CT_MaxBlock) then
        ErrorDesc := 'Need block param'
      else
        ErrorDesc := 'Block not found: '+IntToStr(c);
      ErrorNum := CT_RPC_ErrNum_InvalidBlock;
    end;
  end else if (method='getblockoperations') then
  begin
    // Param "block" contains block
    // Returns a JSON array with items as "Operation resume format"
    c := params.GetAsVariant('block').AsCardinal(CT_MaxBlock);
    if (c>=0) and (c<FNode.Bank.BlocksCount) then
    begin
      pcops := TPCOperationsComp.Create(Nil);
      try
        if not FNode.Bank.LoadOperations(pcops,c) then
        begin
          ErrorNum := CT_RPC_ErrNum_InternalError;
          ErrorDesc := 'Cannot load Block: '+IntToStr(c);
          exit;
        end;
        jsonarr := GetResultArray;
        k := params.AsInteger('max',100);
        j := params.AsInteger('start',0);
        for i := 0 to pcops.Count - 1 do
        begin
          if (i>=j) then
          begin
            if TPCOperation.OperationToOperationResume(c,pcops.Operation[i],pcops.Operation[i].SenderAccount,opr) then
            begin
              opr.NOpInsideBlock:=i;
              opr.time:=pcops.OperationBlock.timestamp;
              opr.Balance := -1; // Don't include!
              FillOperationResumeToJSONObject(opr,jsonarr.GetAsObject(jsonarr.Count));
            end;
          end;
          if (k>0) and ((i+1)>=(j+k)) then
            break;
        end;
        Result := True;
      finally
        pcops.Free;
      end;
    end else
    begin
      if (c=CT_MaxBlock) then
        ErrorDesc := 'Need block param'
      else
        ErrorDesc := 'Block not found: '+IntToStr(c);
      ErrorNum := CT_RPC_ErrNum_InvalidBlock;
    end;
  end else if (method='getaccountoperations') then
  begin
    // Returns all the operations affecting an account in "Operation resume format" as an array
    // Param "account" contains account number
    // Param "depht" (optional or "deep") contains max blocks deep to search (Default: 100)
    // Param "start" and "max" contains starting index and max operations respectively
    c := params.GetAsVariant('account').AsCardinal(CT_MaxAccount);
    if ((c>=0) and (c<FNode.Bank.AccountsCount)) then
    begin
      if (params.IndexOfName('depth')>=0) then
        i := params.AsInteger('depth',100)
      else
        i:=params.AsInteger('deep',100);
      Result := GetAccountOperations(c,GetResultArray,i,params.AsInteger('start',0),params.AsInteger('max',100));
    end else
    begin
      ErrorNum := CT_RPC_ErrNum_InvalidAccount;
      if (c=CT_MaxAccount) then
        ErrorDesc := 'Need account param'
      else
        ErrorDesc := 'Account not found: '+IntToStr(c);
    end;
  end else if (method='getpendings') then
  begin
    // Returns all the operations pending to be included in a block in "Operation resume format" as an array
    // Create result
    GetResultArray;
    for i:=FNode.Operations.Count-1 downto 0 do
    begin
      if not TPCOperation.OperationToOperationResume(0,FNode.Operations.Operation[i],FNode.Operations.Operation[i].SenderAccount,opr) then
      begin
        ErrorNum := CT_RPC_ErrNum_InternalError;
        ErrorDesc := 'Error converting data';
        exit;
      end;
      opr.NOpInsideBlock:=i;
      opr.Balance := FNode.Operations.SafeBoxTransaction.Account(FNode.Operations.Operation[i].SenderAccount).balance;
      FillOperationResumeToJSONObject(opr,GetResultArray.GetAsObject( FNode.Operations.Count-1-i ));
    end;
    Result := true;
  end else if (method='findoperation') then
  begin
    // Search for an operation based on "ophash"
    r := TCrypto.HexaToRaw(params.AsString('ophash',''));
    if (r='') then
    begin
      ErrorNum:=CT_RPC_ErrNum_NotFound;
      ErrorDesc:='param ophash not found or invalid value "'+params.AsString('ophash','')+'"';
      exit;
    end;
    pcops := TPCOperationsComp.Create(Nil);
    try
      if not FNode.FindOperation(pcops,r,c,i) then
      begin
        ErrorNum:=CT_RPC_ErrNum_NotFound;
        ErrorDesc:='ophash not found: "'+params.AsString('ophash','')+'"';
        exit;
      end;
      if not TPCOperation.OperationToOperationResume(c,pcops.Operation[i],pcops.Operation[i].SenderAccount,opr) then
      begin
        ErrorNum := CT_RPC_ErrNum_InternalError;
        ErrorDesc := 'Error 20161026-1';
      end;
      opr.NOpInsideBlock:=i;
      opr.time:=pcops.OperationBlock.timestamp;
      opr.Balance := -1; // don't include
      FillOperationResumeToJSONObject(opr,GetResultObject);
      Result := True;
    finally
      pcops.Free;
    end;
  end else if (method='sendto') then
  begin
    // Sends "amount" coins from "sender" to "target" with "fee"
    // if "payload" is present, it will be encoded using "payload_method"
    // "payload_method" types: "none","dest"(default),"sender","aes"(must provide "pwd" param)
    // Returns a JSON "Operation Resume format" object when successfull
    // Note: "ophash" will contain block "0" = "pending block"
    if not _RPCServer.WalletKeys.IsValidPassword then
    begin
      ErrorNum := CT_RPC_ErrNum_WalletPasswordProtected;
      ErrorDesc := 'Wallet is password protected. Unlock first';
      exit;
    end;
    Result := OpSendTo(params.AsCardinal('sender',CT_MaxAccount),params.AsCardinal('target',CT_MaxAccount),
       ToPascalCoins(params.AsDouble('amount',0)),
       ToPascalCoins(params.AsDouble('fee',0)),
       TCrypto.HexaToRaw(params.AsString('payload','')),
       params.AsString('payload_method','dest'),params.AsString('pwd',''));
  end else if (method='signsendto') then
  begin
    // Create a Transaction operation and adds it into a "rawoperations" (that can include
    // previous operations). This RPC method is usefull for cold storage, because doesn't
    // need to check or verify accounts status/public key, assuming that passed values
    // are ok.
    // Signs a transaction of "amount" coins from "sender" to "target" with "fee", using "sender_enc_pubkey" or "sender_b58_pubkey"
    // and "last_n_operation" of sender. Also, needs "target_enc_pubkey" or "target_b58_pubkey"
    // if "payload" is present, it will be encoded using "payload_method"
    // "payload_method" types: "none","dest"(default),"sender","aes"(must provide "pwd" param)
    // Returns a JSON "Operations info" containing old "rawoperations" plus new Transaction
    if not _RPCServer.WalletKeys.IsValidPassword then
    begin
      ErrorNum := CT_RPC_ErrNum_WalletPasswordProtected;
      ErrorDesc := 'Wallet is password protected. Unlock first';
      exit;
    end;
    if not CapturePubKey('sender_',senderpubkey,ErrorDesc) then
    begin
      ErrorNum := CT_RPC_ErrNum_InvalidPubKey;
      exit;
    end;
    if not CapturePubKey('target_',destpubkey,ErrorDesc) then
    begin
      ErrorNum := CT_RPC_ErrNum_InvalidPubKey;
      exit;
    end;
    Result := SignOpSendTo(
       params.AsString('rawoperations',''),
       params.AsCardinal('sender',CT_MaxAccount),params.AsCardinal('target',CT_MaxAccount),
       senderpubkey,destpubkey,
       params.AsCardinal('last_n_operation',0),
       ToPascalCoins(params.AsDouble('amount',0)),
       ToPascalCoins(params.AsDouble('fee',0)),
       TCrypto.HexaToRaw(params.AsString('payload','')),
       params.AsString('payload_method','dest'),params.AsString('pwd',''));
  end else if (method='changekey') then
  begin
    // Change key of "account" to "new_enc_pubkey" or "new_b58_pubkey" (encoded public key format) with "fee"
    // if "payload" is present, it will be encoded using "payload_method"
    // "payload_method" types: "none","dest"(default),"sender","aes"(must provide "pwd" param)
    // Returns a JSON "Operation Resume format" object when successfull
    // Note: "ophash" will contain block "0" = "pending block"
    if not _RPCServer.WalletKeys.IsValidPassword then
    begin
      ErrorNum := CT_RPC_ErrNum_WalletPasswordProtected;
      ErrorDesc := 'Wallet is password protected. Unlock first';
      exit;
    end;
    if params.IndexOfName('account')<0 then
    begin
      ErrorNum := CT_RPC_ErrNum_InvalidAccount;
      ErrorDesc := 'Need "account" param';
      exit;
    end;
    if not CapturePubKey('new_',account.accountkey,ErrorDesc) then
    begin
      ErrorNum := CT_RPC_ErrNum_InvalidPubKey;
      exit;
    end;
    Result := ChangeAccountKey(params.AsCardinal('account',CT_MaxAccount),
       account.accountkey,
       ToPascalCoins(params.AsDouble('fee',0)),
       TCrypto.HexaToRaw(params.AsString('payload','')),
       params.AsString('payload_method','dest'),params.AsString('pwd',''));
  end else if (method='changekeys') then
  begin
    // Allows a massive change key operation
    // Change key of "accounts" to "new_enc_pubkey" or "new_b58_pubkey" (encoded public key format) with "fee"
    // if "payload" is present, it will be encoded using "payload_method"
    // "payload_method" types: "none","dest"(default),"sender","aes"(must provide "pwd" param)
    // Returns a JSON object with result information
    if not _RPCServer.WalletKeys.IsValidPassword then
    begin
      ErrorNum := CT_RPC_ErrNum_WalletPasswordProtected;
      ErrorDesc := 'Wallet is password protected. Unlock first';
      exit;
    end;
    if params.IndexOfName('accounts')<0 then
    begin
      ErrorNum := CT_RPC_ErrNum_InvalidAccount;
      ErrorDesc := 'Need "accounts" param';
      exit;
    end;
    if not CapturePubKey('new_',account.accountkey,ErrorDesc) then
    begin
      ErrorNum := CT_RPC_ErrNum_InvalidPubKey;
      exit;
    end;
    Result := ChangeAccountsKey(params.AsString('accounts',''),
       account.accountkey,
       ToPascalCoins(params.AsDouble('fee',0)),
       TCrypto.HexaToRaw(params.AsString('payload','')),
       params.AsString('payload_method','dest'),params.AsString('pwd',''));
  end else if (method='signchangekey') then
  begin
    // Create a Change Key operation and adds it into a "rawoperations" (that can include
    // previous operations). This RPC method is usefull for cold storage, because doesn't
    // need to check or verify accounts status/public key, assuming that passed values
    // are ok.
    // Signs a change key of "account" to "new_enc_pubkey" or "new_b58_pubkey" (encoded public key format) with "fee"
    // needs "old_enc_pubkey" or "old_b58_pubkey" that will be used to find private key in wallet to sign
    // and "last_n_operation" of account.
    // if "payload" is present, it will be encoded using "payload_method"
    // "payload_method" types: "none","dest"(default),"sender","aes"(must provide "pwd" param)
    // Returns a JSON "Operations info" containing old "rawoperations" plus new Transaction
    if not _RPCServer.WalletKeys.IsValidPassword then
    begin
      ErrorNum := CT_RPC_ErrNum_WalletPasswordProtected;
      ErrorDesc := 'Wallet is password protected. Unlock first';
      exit;
    end;
    if params.IndexOfName('account')<0 then
    begin
      ErrorNum := CT_RPC_ErrNum_InvalidAccount;
      ErrorDesc := 'Need "account" param';
      exit;
    end;
    if not CapturePubKey('old_',senderpubkey,ErrorDesc) then
    begin
      ErrorNum := CT_RPC_ErrNum_InvalidPubKey;
      exit;
    end;
    if not CapturePubKey('new_',destpubkey,ErrorDesc) then
    begin
      ErrorNum := CT_RPC_ErrNum_InvalidPubKey;
      exit;
    end;
    Result := SignOpChangeKey(params.AsString('rawoperations',''),
       params.AsCardinal('account',CT_MaxAccount),
       senderpubkey,destpubkey,
       params.AsCardinal('last_n_operation',0),
       ToPascalCoins(params.AsDouble('fee',0)),
       TCrypto.HexaToRaw(params.AsString('payload','')),
       params.AsString('payload_method','dest'),params.AsString('pwd',''));
  end else if (method='operationsinfo') then
  begin
    Result := OperationsInfo(params.AsString('rawoperations',''),GetResultArray);
  end else if (method='executeoperations') then
  begin
    Result := ExecuteOperations(params.AsString('rawoperations',''));
  end else if (method='nodestatus') then
  begin
    // Returns a JSON Object with Node status
    GetResultObject.GetAsVariant('ready').Value := False;
    if FNode.IsReady(ansistr) then
    begin
      GetResultObject.GetAsVariant('ready_s').Value := ansistr;
      if TNetData.NetData.NetStatistics.ActiveConnections>0 then
      begin
        GetResultObject.GetAsVariant('ready').Value := True;
        if TNetData.NetData.IsDiscoveringServers then
        begin
          GetResultObject.GetAsVariant('status_s').Value := 'Discovering servers';
        end else if TNetData.NetData.IsGettingNewBlockChainFromClient then
        begin
          GetResultObject.GetAsVariant('status_s').Value := 'Obtaining new blockchain';
        end else
        begin
          GetResultObject.GetAsVariant('status_s').Value := 'Running';
        end;
      end else
      begin
        GetResultObject.GetAsVariant('ready_s').Value := 'Alone in the world...';
      end;
    end else
    begin
      GetResultObject.GetAsVariant('ready_s').Value := ansistr;
    end;
    GetResultObject.GetAsVariant('port').Value:=FNode.NetServer.Port;
    GetResultObject.GetAsVariant('locked').Value:=Not _RPCServer.WalletKeys.IsValidPassword;
    GetResultObject.GetAsVariant('timestamp').Value:=UnivDateTimeToUnix(DateTime2UnivDateTime(now));
    GetResultObject.GetAsVariant('version').Value:=CT_ClientAppVersion;
    GetResultObject.GetAsObject('netprotocol').GetAsVariant('ver').Value := CT_NetProtocol_Version;
    GetResultObject.GetAsObject('netprotocol').GetAsVariant('ver_a').Value := CT_NetProtocol_Available;
    GetResultObject.GetAsVariant('blocks').Value:=FNode.Bank.BlocksCount;
    GetResultObject.GetAsVariant('sbh').Value:=TCrypto.ToHexaString(FNode.Bank.LastOperationBlock.initial_safe_box_hash);
    GetResultObject.GetAsVariant('pow').Value:=TCrypto.ToHexaString(FNode.Bank.LastOperationBlock.proof_of_work);
    GetResultObject.GetAsObject('netstats').GetAsVariant('active').Value:=TNetData.NetData.NetStatistics.ActiveConnections;
    GetResultObject.GetAsObject('netstats').GetAsVariant('clients').Value:=TNetData.NetData.NetStatistics.ClientsConnections;
    GetResultObject.GetAsObject('netstats').GetAsVariant('servers').Value:=TNetData.NetData.NetStatistics.ServersConnectionsWithResponse;
    GetResultObject.GetAsObject('netstats').GetAsVariant('servers_t').Value:=TNetData.NetData.NetStatistics.ServersConnections;
    GetResultObject.GetAsObject('netstats').GetAsVariant('total').Value:=TNetData.NetData.NetStatistics.TotalConnections;
    GetResultObject.GetAsObject('netstats').GetAsVariant('tclients').Value:=TNetData.NetData.NetStatistics.TotalClientsConnections;
    GetResultObject.GetAsObject('netstats').GetAsVariant('tservers').Value:=TNetData.NetData.NetStatistics.TotalServersConnections;
    GetResultObject.GetAsObject('netstats').GetAsVariant('breceived').Value:=TNetData.NetData.NetStatistics.BytesReceived;
    GetResultObject.GetAsObject('netstats').GetAsVariant('bsend').Value:=TNetData.NetData.NetStatistics.BytesSend;
    nsaarr := TNetData.NetData.GetValidNodeServers(true,20);
    for i := low(nsaarr) to High(nsaarr) do
    begin
      jso := GetResultObject.GetAsArray('nodeservers').GetAsObject(i);
      jso.GetAsVariant('ip').Value := nsaarr[i].ip;
      jso.GetAsVariant('port').Value := nsaarr[i].port;
      jso.GetAsVariant('lastcon').Value := nsaarr[i].last_connection;
      jso.GetAsVariant('attempts').Value := nsaarr[i].total_failed_attemps_to_connect;
    end;
    Result := True;
  end else if (method='encodepubkey') then
  begin
    // Creates a encoded public key based on params
    // Param "ec_nid" can be 714=secp256k1 715=secp384r1 729=secp283k1 716=secp521r1
    // Param "x","y" are x and y ec public keys values in hexadecimal based on ec_nid
    // Returns a hexadecimal value containing encoded public key
    account.accountkey.EC_OpenSSL_NID:=params.AsInteger('ec_nid',0);
    account.accountkey.x:=TCrypto.HexaToRaw(params.AsString('x',''));
    account.accountkey.y:=TCrypto.HexaToRaw(params.AsString('y',''));
    if (account.accountkey.EC_OpenSSL_NID=0) or (account.accountkey.x='') or (account.accountkey.y='') then
    begin
      ErrorDesc:= 'Need params "ec_nid","x","y" to encodepubkey';
      ErrorNum:= CT_RPC_ErrNum_InvalidPubKey;
      exit;
    end;
    if TAccountComp.IsValidAccountKey(account.accountkey,ansistr) then
    begin
      jsonresponse.GetAsVariant('result').Value:=TCrypto.ToHexaString(TAccountComp.AccountKey2RawString(account.accountkey));
      Result := True;
    end else
    begin
      ErrorDesc:= ansistr;
      ErrorNum:= CT_RPC_ErrNum_InvalidPubKey;
    end;
  end else if (method='decodepubkey') then
  begin
    // Returns "ec_nid", "x" and "y" of an encoded public key (x and y in hexadecimal)
    // Must provide:
    // - Param "enc_pubkey" is an hexadecimal encoded public key (see 'encodepubkey')
    // or
    // - Param "b58_pubkey" is a Base58 encoded public key
    if not CapturePubKey('',account.accountkey,ErrorDesc) then
    begin
      ErrorNum := CT_RPC_ErrNum_InvalidPubKey;
      exit;
    end;
    if (TAccountComp.IsValidAccountKey(account.accountkey,ansistr)) then
    begin
      FillPublicKeyObject(account.accountkey,GetResultObject);
      Result := True;
    end else
    begin
      ErrorDesc:= ansistr;
      ErrorNum:= CT_RPC_ErrNum_InvalidPubKey;
    end;
  end else if (method='payloadencrypt') then
  begin
    // Encrypts a "payload" using "payload_method"
    // "payload_method" types: "none","pubkey"(must provide "enc_pubkey" or "b58_pubkey"),"aes"(must provide "pwd" param)
    // if payload is "pubkey"
    // Returns an hexa string with encrypted payload
    if (params.AsString('payload','')='') then
    begin
      ErrorNum:= CT_RPC_ErrNum_InvalidData;
      ErrorDesc := 'Need param "payload"';
      exit;
    end;
    opr.newKey := CT_TWalletKey_NUL.AccountKey;
    if (params.IndexOfName('enc_pubkey')>=0) or (params.IndexOfName('b58_pubkey')>=0) then
    begin
      if not (CapturePubKey('',opr.newKey,ErrorDesc)) then
      begin
        ErrorNum := CT_RPC_ErrNum_InvalidPubKey;
        exit;
      end;
    end;
    Result := DoEncrypt(TCrypto.HexaToRaw(params.AsString('payload','')),
       opr.newKey,
       params.AsString('payload_method',''),params.AsString('pwd',''));
  end else if (method='payloaddecrypt') then
  begin
    // Decrypts a "payload" searching for wallet private keys and for array of strings in "pwds" param
    // Returns an JSON Object with "result" (Boolean) and
    if (params.AsString('payload','')='') then
    begin
      ErrorNum:= CT_RPC_ErrNum_InvalidData;
      ErrorDesc := 'Need param "payload"';
      exit;
    end;
    if not _RPCServer.WalletKeys.IsValidPassword then
    begin
      ErrorNum := CT_RPC_ErrNum_WalletPasswordProtected;
      ErrorDesc := 'Wallet is password protected. Unlock first';
      exit;
    end;
    Result := DoDecrypt(TCrypto.HexaToRaw(params.AsString('payload','')),params.GetAsArray('pwds'));
  end else if (method='getconnections') then
  begin
    // Returns an array of connections objects with info about state
    GetConnections;
    Result := true;
  end else if (method='addnewkey') then
  begin
    // Creates a new private key and stores it on the wallet, returning Public key JSON object
    // Param "ec_nid" can be 714=secp256k1 715=secp384r1 729=secp283k1 716=secp521r1. (Default = CT_Default_EC_OpenSSL_NID)
    // Param "name" is name for this address
    if not _RPCServer.WalletKeys.IsValidPassword then
    begin
      ErrorNum := CT_RPC_ErrNum_WalletPasswordProtected;
      ErrorDesc := 'Wallet is password protected. Unlock first';
      exit;
    end;
    ecpkey := TECPrivateKey.Create;
    try
      ecpkey.GenerateRandomPrivateKey(params.AsInteger('ec_nid',CT_Default_EC_OpenSSL_NID));
      _RPCServer.FWalletKeys.AddPrivateKey(params.AsString('name',DateTimeToStr(now)),ecpkey);
      FillPublicKeyObject(ecpkey.PublicKey,GetResultObject);
      Result := true;
    finally
      ecpkey.Free;
    end;
  end else if (method='lock') then
  begin
    jsonresponse.GetAsVariant('result').Value := _RPCServer.WalletKeys.LockWallet;
    Result := true;
  end else if (method='unlock') then
  begin
    // Unlocks the Wallet with "pwd" password
    // Returns Boolean if wallet is unlocked
    if (params.IndexOfName('pwd')<0) then
    begin
      ErrorNum:= CT_RPC_ErrNum_InvalidData;
      ErrorDesc := 'Need param "pwd"';
      exit;
    end;
    if not _RPCServer.WalletKeys.IsValidPassword then
    begin
      _RPCServer.WalletKeys.WalletPassword:=params.AsString('pwd','');
    end;
    jsonresponse.GetAsVariant('result').Value := _RPCServer.WalletKeys.IsValidPassword;
    Result := true;
  end else if (method='setwalletpassword') then
  begin
    // Changes the Wallet password with "pwd" param
    // Must be unlocked first
    // Returns Boolean if wallet password changed
    if not _RPCServer.WalletKeys.IsValidPassword then
    begin
      ErrorNum := CT_RPC_ErrNum_WalletPasswordProtected;
      ErrorDesc := 'Wallet is password protected. Unlock first';
      exit;
    end;
    //
    if (params.IndexOfName('pwd')<0) then
    begin
      ErrorNum:= CT_RPC_ErrNum_InvalidData;
      ErrorDesc := 'Need param "pwd"';
      exit;
    end;
    _RPCServer.WalletKeys.WalletPassword:=params.AsString('pwd','');
    jsonresponse.GetAsVariant('result').Value := _RPCServer.WalletKeys.IsValidPassword;
    Result := true;
  end else if (method='stopnode') then
  begin
    // Stops communications to other nodes
    FNode.NetServer.Active := false;
    TNetData.NetData.NetConnectionsActive:=false;
    jsonresponse.GetAsVariant('result').Value := true;
    Result := true;
  end else if (method='startnode') then
  begin
    // Stops communications to other nodes
    FNode.NetServer.Active := true;
    TNetData.NetData.NetConnectionsActive:=true;
    jsonresponse.GetAsVariant('result').Value := true;
    Result := true;
  end else
  begin
    ErrorNum := CT_RPC_ErrNum_MethodNotFound;
    ErrorDesc := 'Method not found: "'+method+'"';
  end;
end;

{ TRPCServerThread }

constructor TRPCServerThread.Create(Port: Word);
begin
  TLog.NewLog(ltInfo,ClassName,'Activating RPC-JSON Server on port '+inttostr(Port));
  FServerSocket:=TTCPBlockSocket.create;
  FPort := Port;
  inherited create(false);
end;

destructor TRPCServerThread.Destroy;
begin
  TLog.NewLog(ltInfo,ClassName,'Stoping RPC-JSON Server');
  FreeAndNil(FServerSocket);
  inherited Destroy;
end;

procedure TRPCServerThread.BCExecute;
var
  ClientSock:TSocket;
begin
  with FServerSocket do
  begin
    CreateSocket;
    setLinger(true,10000);
    bind('0.0.0.0',Inttostr(FPort));
    listen;
    repeat
      if terminated then
        break;
      try
        if canread(1000) then
        begin
          ClientSock:=accept;
          if lastError=0 then
          begin
            TRPCProcess.create(ClientSock);
          end;
        end;
      except
        on E:Exception do
        begin
          TLog.NewLog(ltError,Classname,'Error '+E.ClassName+':'+E.Message);
        end;
      end;
      sleep(1);
    until false;
  end;
end;

end.

