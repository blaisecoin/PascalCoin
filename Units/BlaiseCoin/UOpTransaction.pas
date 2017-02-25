{
  Copyright (c) 2016 by Albert Molina
  Copyright (c) 2017 by BlaiseCoin developers

  Distributed under the MIT software license, see the accompanying file LICENSE
  or visit http://www.opensource.org/licenses/mit-license.php.

  This unit is a part of BlaiseCoin, a P2P crypto-currency.
}

unit UOpTransaction;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface

uses UCrypto, UBlockChain, Classes, UAccounts;

Type
  // Operations Type
  TOpTransactionData = record
    sender: Cardinal;
    n_operation : Cardinal;
    target: Cardinal;
    amount: UInt64;
    fee: UInt64;
    payload: AnsiString;
    public_key: TECDSA_Public;
    sign: TECDSA_SIG;
  end;

  TOpChangeKeyData = record
    account: Cardinal;
    n_operation : Cardinal;
    fee: UInt64;
    payload: AnsiString;
    public_key: TECDSA_Public;
    new_accountkey: TAccountKey;
    sign: TECDSA_SIG;
  end;

  TOpRecoverFundsData = record
    account: Cardinal;
    n_operation : Cardinal;
    fee: UInt64;
  end;

  { TOpTransaction }

  TOpTransaction = class(TPCOperation)
  private
    FData : TOpTransactionData;
  public
    function GetOperationBufferToHash : TRawBytes; override;
    function DoOperation(AccountTransaction : TPCSafeBoxTransaction; var errors : AnsiString) : Boolean; override;
    function SaveToStream(Stream : TStream) : Boolean; override;
    function LoadFromStream(Stream : TStream) : Boolean; override;
    procedure AffectedAccounts(list : TList); override;
    //
    class function GetTransactionHashToSign(const trans : TOpTransactionData) : TRawBytes;
    class function DoSignOperation(key : TECPrivateKey; var trans : TOpTransactionData) : Boolean;
    class function OpType : Byte; override;
    function OperationAmount : Int64; override;
    function OperationFee : UInt64; override;
    function OperationPayload : TRawBytes; override;
    function SenderAccount : Cardinal; override;
    function N_Operation : Cardinal; override;
    property Data : TOpTransactionData read FData;

    constructor Create(sender, n_operation, target: Cardinal; key: TECPrivateKey; amount, fee: UInt64; payload: AnsiString);
    function toString : String; Override;
  end;

  { TOpChangeKey }

  TOpChangeKey = class(TPCOperation)
  private
    FData : TOpChangeKeyData;
  public
    class function GetOperationHashToSign(const op : TOpChangeKeyData) : TRawBytes;
    class function DoSignOperation(key : TECPrivateKey; var op : TOpChangeKeyData) : Boolean;
    class function OpType : Byte; override;

    function GetOperationBufferToHash : TRawBytes; override;
    function DoOperation(AccountTransaction : TPCSafeBoxTransaction; var errors : AnsiString) : Boolean; override;
    function SaveToStream(Stream : TStream) : Boolean; override;
    function LoadFromStream(Stream : TStream) : Boolean; override;
    function OperationAmount : Int64; override;
    function OperationFee : UInt64; override;
    function OperationPayload : TRawBytes; override;
    function SenderAccount : Cardinal; override;
    function N_Operation : Cardinal; override;
    procedure AffectedAccounts(list : TList); override;
    constructor Create(account_number, n_operation: Cardinal; key:TECPrivateKey; new_account_key : TAccountKey; fee: UInt64; payload: AnsiString);
    property Data : TOpChangeKeyData read FData;
    function toString : String; Override;
  end;

  { TOpRecoverFunds }

  TOpRecoverFunds = class(TPCOperation)
  private
    FData : TOpRecoverFundsData;
  public
    class function OpType : Byte; override;

    function GetOperationBufferToHash : TRawBytes; override;
    function DoOperation(AccountTransaction : TPCSafeBoxTransaction; var errors : AnsiString) : Boolean; override;
    function SaveToStream(Stream : TStream) : Boolean; override;
    function LoadFromStream(Stream : TStream) : Boolean; override;
    function OperationAmount : Int64; override;
    function OperationFee : UInt64; override;
    function OperationPayload : TRawBytes; override;
    function SenderAccount : Cardinal; override;
    function N_Operation : Cardinal; override;
    procedure AffectedAccounts(list : TList); override;
    constructor Create(account_number, n_operation: Cardinal; fee: UInt64);
    property Data : TOpRecoverFundsData read FData;
    function toString : String; Override;
  end;

procedure RegisterOperationsClass;

implementation

uses
  SysUtils, UConst, ULog, UStreamOp;

procedure RegisterOperationsClass;
Begin
  TPCOperationsComp.RegisterOperationClass(TOpTransaction);
  TPCOperationsComp.RegisterOperationClass(TOpChangeKey);
  TPCOperationsComp.RegisterOperationClass(TOpRecoverFunds);
End;

{ TOpTransaction }

procedure TOpTransaction.AffectedAccounts(list: TList);
begin
  list.Add(TObject(FData.sender));
  list.Add(TObject(FData.target));
end;

constructor TOpTransaction.Create(sender, n_operation, target: Cardinal;
  key: TECPrivateKey; amount, fee: UInt64; payload: AnsiString);
begin
  FData.sender := sender;
  FData.n_operation := n_operation;
  FData.target := target;
  FData.amount := amount;
  FData.fee := fee;
  FData.payload := payload;
  FData.public_key := key.PublicKey;
  if not DoSignOperation(key,FData) then begin
    TLog.NewLog(lterror,Classname,'Error signing a new Transaction');
    FHasValidSignature := False;
  end else FHasValidSignature := True;
end;

function TOpTransaction.DoOperation(AccountTransaction : TPCSafeBoxTransaction; var errors : AnsiString): Boolean;
var
  totalamount : Cardinal;
  sender,target : TAccount;
  _h : TRawBytes;
begin
  Result := False;
  errors := '';
  //
  if (FData.sender>=AccountTransaction.FreezedSafeBox.AccountsCount) then
  begin
    errors := Format('Invalid sender %d',[FData.sender]);
    exit;
  end;
  if (FData.target>=AccountTransaction.FreezedSafeBox.AccountsCount) then
  begin
    errors := Format('Invalid target %d',[FData.target]);
    exit;
  end;
  if (FData.sender=FData.target) then begin
    errors := Format('Sender=Target %d',[FData.sender]);
    exit;
  end;
  if TAccountComp.IsAccountBlockedByProtocol(FData.sender,AccountTransaction.FreezedSafeBox.BlocksCount) then
  begin
    errors := Format('sender (%d) is blocked for protocol',[FData.sender]);
    exit;
  end;
  if TAccountComp.IsAccountBlockedByProtocol(FData.target,AccountTransaction.FreezedSafeBox.BlocksCount) then
  begin
    errors := Format('target (%d) is blocked for protocol',[FData.target]);
    exit;
  end;
  if (FData.amount<=0) or (FData.amount>CT_MaxTransactionAmount) then
  begin
    errors := Format('Invalid amount %d (0 or max: %d)',[FData.amount,CT_MaxTransactionAmount]);
    exit;
  end;
  if (FData.fee<0) or (FData.fee>CT_MaxTransactionFee) then
  begin
    errors := Format('Invalid fee %d (max %d)',[FData.fee,CT_MaxTransactionFee]);
    exit;
  end;
  if (length(FData.payload)>CT_MaxPayloadSize) then
  begin
    errors := 'Invalid Payload size:'+inttostr(length(FData.payload))+' (Max: '+inttostr(CT_MaxPayloadSize)+')';
  end;

  sender := AccountTransaction.Account(FData.sender);
  target := AccountTransaction.Account(FData.target);
  if ((sender.n_operation+1)<>FData.n_operation) then
  begin
    errors := Format('Invalid n_operation %d (expected %d)',[FData.n_operation,sender.n_operation+1]);
    exit;
  end;
  totalamount := FData.amount + FData.fee;
  if (sender.balance<totalamount) then
  begin
    errors := Format('Insuficient founds %d < (%d + %d = %d)',[sender.balance,FData.amount,FData.fee,totalamount]);
    exit;
  end;
  if (target.balance+FData.amount>CT_MaxWalletAmount) then
  begin
    errors := Format('Target cannot accept this transaction due to max amount %d+%d=%d > %d',[target.balance,FData.amount,target.balance+FData.amount,CT_MaxWalletAmount]);
    exit;
  end;
  // Build 1.4
  if (FData.public_key.EC_OpenSSL_NID<>CT_TECDSA_Public_Nul.EC_OpenSSL_NID) and (not TAccountComp.Equal(FData.public_key,sender.accountkey)) then
  begin
    errors := Format('Invalid sender public key for account %d. Distinct from SafeBox public key! %s <> %s',[
      FData.sender,
      TCrypto.ToHexaString(TAccountComp.AccountKey2RawString(FData.public_key)),
      TCrypto.ToHexaString(TAccountComp.AccountKey2RawString(sender.accountkey))]);
    exit;
  end;
  // Check signature
  _h := GetTransactionHashToSign(FData);
  if (not TCrypto.ECDSAVerify(sender.accountkey,_h,FData.sign)) then
  begin
    errors := 'Invalid sign';
    FHasValidSignature := False;
    exit;
  end else FHasValidSignature := True;
  //
  FPrevious_Sender_updated_block := sender.updated_block;
  FPrevious_Destination_updated_block := target.updated_block;
  // Do operation
  Result := AccountTransaction.TransferAmount(FData.sender,FData.target,FData.n_operation,FData.amount,FData.fee,errors);
end;

class function TOpTransaction.DoSignOperation(key : TECPrivateKey; var trans : TOpTransactionData) : Boolean;
var
  s : AnsiString;
  _sign : TECDSA_SIG;
begin
  if not Assigned(key.PrivateKey) then
  begin
    Result := False;
    trans.sign.r:='';
    trans.sign.s:='';
    exit;
  end;
  s := GetTransactionHashToSign(trans);
  try
    _sign := TCrypto.ECDSASign(key.PrivateKey,s);
    trans.sign := _sign;
    Result := True;
  except
    trans.sign.r:='';
    trans.sign.s:='';
    Result := False;
  end;
  SetLength(s,0);
end;

function TOpTransaction.GetOperationBufferToHash: TRawBytes;
var
  ms : TMemoryStream;
begin
  ms := TMemoryStream.Create;
  try
    ms.WriteBuffer(FData.sender, SizeOf(FData.sender));
    ms.WriteBuffer(FData.n_operation, SizeOf(FData.n_operation));
    ms.WriteBuffer(FData.target, SizeOf(FData.target));
    ms.WriteBuffer(FData.amount, SizeOf(FData.amount));
    ms.WriteBuffer(FData.fee, SizeOf(FData.fee));
    TStreamOp.WriteAnsiString(ms, FData.payload);
    ms.WriteBuffer(FData.public_key.EC_OpenSSL_NID, SizeOf(FData.public_key.EC_OpenSSL_NID));
    TStreamOp.WriteAnsiString(ms, FData.public_key.x);
    TStreamOp.WriteAnsiString(ms, FData.public_key.y);
    TStreamOp.WriteAnsiString(ms, FData.sign.r);
    TStreamOp.WriteAnsiString(ms, FData.sign.s);
    SetLength(Result, ms.Size);
    ms.Position := 0;
    ms.ReadBuffer(Result[1], ms.Size);
  finally
    ms.Free;
  end;
end;

class function TOpTransaction.GetTransactionHashToSign(const trans: TOpTransactionData): TRawBytes;
var ms : TMemoryStream;
begin
  ms := TMemoryStream.Create;
  try
    ms.WriteBuffer(trans.sender, SizeOf(trans.sender));
    ms.WriteBuffer(trans.n_operation, SizeOf(trans.n_operation));
    ms.WriteBuffer(trans.target, SizeOf(trans.target));
    ms.WriteBuffer(trans.amount, SizeOf(trans.amount));
    ms.WriteBuffer(trans.fee, SizeOf(trans.fee));
    TStreamOp.WriteAnsiString(ms, trans.payload);
    ms.WriteBuffer(trans.public_key.EC_OpenSSL_NID, SizeOf(trans.public_key.EC_OpenSSL_NID));
    TStreamOp.WriteAnsiString(ms, trans.public_key.x);
    TStreamOp.WriteAnsiString(ms, trans.public_key.y);
    SetLength(Result, ms.Size);
    ms.Position := 0;
    ms.ReadBuffer(Result[1], ms.Size);
  finally
    ms.Free;
  end;
end;

function TOpTransaction.LoadFromStream(Stream: TStream): Boolean;
begin
  Result := False;
  if Stream.Size - Stream.Position < 28 then
    exit; // Invalid stream
  Stream.ReadBuffer(FData.sender, SizeOf(FData.sender));
  Stream.ReadBuffer(FData.n_operation, SizeOf(FData.n_operation));
  Stream.ReadBuffer(FData.target, SizeOf(FData.target));
  Stream.ReadBuffer(FData.amount, SizeOf(FData.amount));
  Stream.ReadBuffer(FData.fee, SizeOf(FData.fee));
  if TStreamOp.ReadAnsiString(Stream, FData.payload) < 0 then
    exit;
  if Stream.Read(FData.public_key.EC_OpenSSL_NID, SizeOf(FData.public_key.EC_OpenSSL_NID)) < 0 then
    exit;
  if TStreamOp.ReadAnsiString(Stream, FData.public_key.x) < 0 then
    exit;
  if TStreamOp.ReadAnsiString(Stream, FData.public_key.y) < 0 then
    exit;
  if TStreamOp.ReadAnsiString(Stream, FData.sign.r) < 0 then
    exit;
  if TStreamOp.ReadAnsiString(Stream, FData.sign.s) < 0 then
    exit;
  Result := True;
end;

function TOpTransaction.OperationAmount: Int64;
begin
  Result := FData.amount;
end;

function TOpTransaction.OperationFee: UInt64;
begin
  Result := FData.fee;
end;

function TOpTransaction.OperationPayload: TRawBytes;
begin
  Result := FData.payload;
end;

class function TOpTransaction.OpType: Byte;
begin
  Result := CT_Op_Transaction;
end;

function TOpTransaction.SaveToStream(Stream: TStream): Boolean;
begin
  Stream.WriteBuffer(FData.sender, SizeOf(FData.sender));
  Stream.WriteBuffer(FData.n_operation, SizeOf(FData.n_operation));
  Stream.WriteBuffer(FData.target, SizeOf(FData.target));
  Stream.WriteBuffer(FData.amount, SizeOf(FData.amount));
  Stream.WriteBuffer(FData.fee, SizeOf(FData.fee));
  TStreamOp.WriteAnsiString(Stream, FData.payload);
  Stream.WriteBuffer(FData.public_key.EC_OpenSSL_NID, SizeOf(FData.public_key.EC_OpenSSL_NID));
  TStreamOp.WriteAnsiString(Stream, FData.public_key.x);
  TStreamOp.WriteAnsiString(Stream, FData.public_key.y);
  TStreamOp.WriteAnsiString(Stream, FData.sign.r);
  TStreamOp.WriteAnsiString(Stream, FData.sign.s);
  Result := True;
end;

function TOpTransaction.SenderAccount: Cardinal;
begin
  Result := FData.sender;
end;

function TOpTransaction.N_Operation: Cardinal;
begin
  Result := FData.n_operation;
end;

function TOpTransaction.toString: String;
begin
  Result := Format('Transaction from %s to %s amount:%s fee:%s (n_op:%d) payload size:%d',[
     TAccountComp.AccountNumberToAccountTxtNumber(FData.sender),
     TAccountComp.AccountNumberToAccountTxtNumber(FData.target),
     TAccountComp.FormatMoney(FData.amount),TAccountComp.FormatMoney(FData.fee),FData.n_operation,Length(FData.payload)]);
end;

{ TOpChangeKey }

procedure TOpChangeKey.AffectedAccounts(list: TList);
begin
  list.Add(TObject(FData.account));
end;

constructor TOpChangeKey.Create(account_number, n_operation: Cardinal; key:TECPrivateKey; new_account_key : TAccountKey; fee: UInt64; payload: AnsiString);
begin
  FData.account := account_number;
  FData.n_operation := n_operation;
  FData.fee := fee;
  FData.payload := payload;
  FData.public_key := key.PublicKey;
  FData.new_accountkey := new_account_key;
  if not DoSignOperation(key,FData) then
  begin
    TLog.NewLog(lterror,Classname,'Error signing a new Change key');
    FHasValidSignature := False;
  end
  else
    FHasValidSignature := True;
end;

function TOpChangeKey.DoOperation(AccountTransaction : TPCSafeBoxTransaction; var errors: AnsiString): Boolean;
var account : TAccount;
begin
  Result := False;
  if (FData.account>=AccountTransaction.FreezedSafeBox.AccountsCount) then
  begin
    errors := 'Invalid account number';
    exit;
  end;
  if TAccountComp.IsAccountBlockedByProtocol(FData.account, AccountTransaction.FreezedSafeBox.BlocksCount) then
  begin
    errors := 'account is blocked for protocol';
    exit;
  end;
  if (FData.fee<0) or (FData.fee>CT_MaxTransactionFee) then
  begin
    errors := 'Invalid fee: '+Inttostr(FData.fee);
    exit;
  end;
  account := AccountTransaction.Account(FData.account);
  if ((account.n_operation+1)<>FData.n_operation) then
  begin
    errors := 'Invalid n_operation';
    exit;
  end;
  if (account.balance<FData.fee) then
  begin
    errors := 'Insuficient founds';
    exit;
  end;
  if (length(FData.payload)>CT_MaxPayloadSize) then
  begin
    errors := 'Invalid Payload size:'+inttostr(length(FData.payload))+' (Max: '+inttostr(CT_MaxPayloadSize)+')';
  end;
  if not TAccountComp.IsValidAccountKey( FData.new_accountkey, errors ) then
  begin
    exit;
  end;
  // Build 1.4
  if (FData.public_key.EC_OpenSSL_NID<>CT_TECDSA_Public_Nul.EC_OpenSSL_NID) and (not TAccountComp.Equal(FData.public_key,account.accountkey)) then
  begin
    errors := Format('Invalid public key for account %d. Distinct from SafeBox public key! %s <> %s',[
      FData.account,
      TCrypto.ToHexaString(TAccountComp.AccountKey2RawString(FData.public_key)),
      TCrypto.ToHexaString(TAccountComp.AccountKey2RawString(account.accountkey))]);
    exit;
  end;

  if not TCrypto.ECDSAVerify(account.accountkey,GetOperationHashToSign(FData),FData.sign) then
  begin
    errors := 'Invalid sign';
    FHasValidSignature := False;
    exit;
  end
  else
    FHasValidSignature := True;
  FPrevious_Sender_updated_block := account.updated_block;
  Result := AccountTransaction.UpdateAccountkey(FData.account,FData.n_operation,FData.new_accountkey,FData.fee,errors);
end;

class function TOpChangeKey.DoSignOperation(key: TECPrivateKey; var op: TOpChangeKeyData): Boolean;
var s : AnsiString;
  _sign : TECDSA_SIG;
begin
  s := GetOperationHashToSign(op);
  try
    _sign := TCrypto.ECDSASign(key.PrivateKey,s);
    op.sign := _sign;
    Result := True;
  except
    on E:Exception do
    begin
      Result := False;
      TLog.NewLog(lterror,ClassName,'Error signing ChangeKey operation: '+E.Message);
    end;
  end;
end;

function TOpChangeKey.GetOperationBufferToHash: TRawBytes;
var ms : TMemoryStream;
  s : AnsiString;
begin
  ms := TMemoryStream.Create;
  try
    ms.WriteBuffer(FData.account, SizeOf(FData.account));
    ms.WriteBuffer(FData.n_operation, SizeOf(FData.n_operation));
    ms.WriteBuffer(FData.fee, SizeOf(FData.fee));
    TStreamOp.WriteAnsiString(ms, FData.payload);
    ms.WriteBuffer(FData.public_key.EC_OpenSSL_NID,SizeOf(FData.public_key.EC_OpenSSL_NID));
    TStreamOp.WriteAnsiString(ms, FData.public_key.x);
    TStreamOp.WriteAnsiString(ms, FData.public_key.y);
    s := TAccountComp.AccountKey2RawString(FData.new_accountkey);
    TStreamOp.WriteAnsiString(ms, s);
    TStreamOp.WriteAnsiString(ms, FData.sign.r);
    TStreamOp.WriteAnsiString(ms, FData.sign.s);
    ms.Position := 0;
    SetLength(Result, ms.Size);
    ms.ReadBuffer(Result[1], ms.Size);
  finally
    ms.Free;
  end;
end;

class function TOpChangeKey.GetOperationHashToSign(const op: TOpChangeKeyData): TRawBytes;
var ms : TMemoryStream;
  s : AnsiString;
begin
  ms := TMemoryStream.Create;
  try
    ms.WriteBuffer(op.account, SizeOf(op.account));
    ms.WriteBuffer(op.n_operation, SizeOf(op.n_operation));
    ms.WriteBuffer(op.fee, SizeOf(op.fee));
    TStreamOp.WriteAnsiString(ms, op.payload);
    ms.WriteBuffer(op.public_key.EC_OpenSSL_NID, SizeOf(op.public_key.EC_OpenSSL_NID));
    TStreamOp.WriteAnsiString(ms, op.public_key.x);
    TStreamOp.WriteAnsiString(ms, op.public_key.y);
    s := TAccountComp.AccountKey2RawString(op.new_accountkey);
    TStreamOp.WriteAnsiString(ms, s);
    ms.Position := 0;
    SetLength(Result, ms.Size);
    ms.ReadBuffer(Result[1], ms.Size);
  finally
    ms.Free;
  end;
end;

function TOpChangeKey.LoadFromStream(Stream: TStream): Boolean;
var s : AnsiString;
begin
  Result := False;
  if Stream.Size - Stream.Position < 16  then
    exit; // Invalid stream
  Stream.ReadBuffer(FData.account, SizeOf(FData.account));
  Stream.ReadBuffer(FData.n_operation, SizeOf(FData.n_operation));
  Stream.ReadBuffer(FData.fee, SizeOf(FData.fee));
  if TStreamOp.ReadAnsiString(Stream, FData.payload) < 0 then
    exit;
  if Stream.Read(FData.public_key.EC_OpenSSL_NID, SizeOf(FData.public_key.EC_OpenSSL_NID)) < 0 then
    exit;
  if TStreamOp.ReadAnsiString(Stream, FData.public_key.x) < 0 then
    exit;
  if TStreamOp.ReadAnsiString(Stream, FData.public_key.y) < 0 then
    exit;
  if TStreamOp.ReadAnsiString(Stream, s) < 0 then
    exit;
  FData.new_accountkey := TAccountComp.RawString2Accountkey(s);
  if TStreamOp.ReadAnsiString(Stream, FData.sign.r) < 0 then
    exit;
  if TStreamOp.ReadAnsiString(Stream, FData.sign.s) < 0 then
    exit;
  Result := True;
end;

function TOpChangeKey.OperationAmount: Int64;
begin
  Result := 0;
end;

function TOpChangeKey.OperationFee: UInt64;
begin
  Result := FData.fee;
end;

function TOpChangeKey.OperationPayload: TRawBytes;
begin
  Result := FData.payload;
end;

class function TOpChangeKey.OpType: Byte;
begin
  Result := CT_Op_Changekey;
end;

function TOpChangeKey.SaveToStream(Stream: TStream): Boolean;
begin
  Stream.WriteBuffer(FData.account, SizeOf(FData.account));
  Stream.WriteBuffer(FData.n_operation, SizeOf(FData.n_operation));
  Stream.WriteBuffer(FData.fee, SizeOf(FData.fee));
  TStreamOp.WriteAnsiString(Stream, FData.payload);
  Stream.WriteBuffer(FData.public_key.EC_OpenSSL_NID, SizeOf(FData.public_key.EC_OpenSSL_NID));
  TStreamOp.WriteAnsiString(Stream, FData.public_key.x);
  TStreamOp.WriteAnsiString(Stream, FData.public_key.y);
  TStreamOp.WriteAnsiString(Stream, TAccountComp.AccountKey2RawString(FData.new_accountkey));
  TStreamOp.WriteAnsiString(Stream, FData.sign.r);
  TStreamOp.WriteAnsiString(Stream, FData.sign.s);
  Result := True;
end;

function TOpChangeKey.SenderAccount: Cardinal;
begin
  Result := FData.account;
end;

function TOpChangeKey.N_Operation: Cardinal;
begin
  Result := FData.n_operation;
end;

function TOpChangeKey.toString: String;
begin
  Result := Format('Change key of %s to new key: %s fee:%s (n_op:%d) payload size:%d',[
    TAccountComp.AccountNumberToAccountTxtNumber(FData.account),
    TAccountComp.GetECInfoTxt(FData.new_accountkey.EC_OpenSSL_NID),
    TAccountComp.FormatMoney(FData.fee),FData.n_operation,Length(FData.payload)]);
end;

{ TOpRecoverFunds }

constructor TOpRecoverFunds.Create(account_number, n_operation : Cardinal; fee: UInt64);
begin
  FData.account := account_number;
  FData.n_operation := n_operation;
  FData.fee := fee;
  FHasValidSignature := True; // Recover funds doesn't need a signature
end;

procedure TOpRecoverFunds.AffectedAccounts(list: TList);
begin
  list.Add(TObject(FData.account));
end;

function TOpRecoverFunds.DoOperation(AccountTransaction : TPCSafeBoxTransaction; var errors: AnsiString): Boolean;
var acc : TAccount;
begin
  Result := False;
  if TAccountComp.IsAccountBlockedByProtocol(FData.account,AccountTransaction.FreezedSafeBox.BlocksCount) then
  begin
    errors := 'account is blocked for protocol';
    exit;
  end;
  acc := AccountTransaction.Account(FData.account);
  if (acc.updated_block + CT_RecoverFoundsWaitInactiveCount >= AccountTransaction.FreezedSafeBox.BlocksCount) then
  begin
    errors := Format('Account is active to recover founds! Account %d Updated %d + %d >= BlockCount : %d',[FData.account,acc.updated_block,CT_RecoverFoundsWaitInactiveCount,AccountTransaction.FreezedSafeBox.BlocksCount]);
    exit;
  end;
  // Build 1.0.8 ... there was a BUG. Need to prevent recent created accounts
  if (TAccountComp.AccountBlock(FData.account) + CT_RecoverFoundsWaitInactiveCount >= AccountTransaction.FreezedSafeBox.BlocksCount) then
  begin
    errors := Format('AccountBlock is active to recover founds! AccountBlock %d + %d >= BlockCount : %d',[TAccountComp.AccountBlock(FData.account),CT_RecoverFoundsWaitInactiveCount,AccountTransaction.FreezedSafeBox.BlocksCount]);
    exit;
  end;
  if ((acc.n_operation+1)<>FData.n_operation) then
  begin
    errors := 'Invalid n_operation';
    exit;
  end;
  if (FData.fee<=0) or (FData.fee>CT_MaxTransactionFee) then
  begin
    errors := 'Invalid fee '+Inttostr(FData.fee);
    exit;
  end;
  if (acc.balance<FData.fee) then
  begin
    errors := 'Insuficient founds';
    exit;
  end;
  FPrevious_Sender_updated_block := acc.updated_block;
  Result := AccountTransaction.TransferAmount(FData.account,FData.account,FData.n_operation,0,FData.fee,errors);
end;

function TOpRecoverFunds.GetOperationBufferToHash: TRawBytes;
var ms : TMemoryStream;
begin
  ms := TMemoryStream.Create;
  try
    ms.WriteBuffer(FData.account, SizeOf(FData.account));
    ms.WriteBuffer(FData.n_operation, SizeOf(FData.n_operation));
    ms.WriteBuffer(FData.fee, SizeOf(FData.fee));
    ms.Position := 0;
    SetLength(Result, ms.Size);
    ms.ReadBuffer(Result[1], ms.Size);
  finally
    ms.Free;
  end;
end;

function TOpRecoverFunds.LoadFromStream(Stream: TStream): Boolean;
begin
  Result := False;
  if Stream.Size - Stream.Position < 16 then
    exit;
  Stream.ReadBuffer(FData.account, SizeOf(FData.account));
  Stream.ReadBuffer(FData.n_operation, SizeOf(FData.n_operation));
  Stream.ReadBuffer(FData.fee, SizeOf(FData.fee));
  Result := True;
end;

function TOpRecoverFunds.OperationAmount: Int64;
begin
  Result := 0;
end;

function TOpRecoverFunds.OperationFee: UInt64;
begin
  Result := FData.fee;
end;

function TOpRecoverFunds.OperationPayload: TRawBytes;
begin
  Result := '';
end;

class function TOpRecoverFunds.OpType: Byte;
begin
  Result := CT_Op_Recover;
end;

function TOpRecoverFunds.SaveToStream(Stream: TStream): Boolean;
begin
  Stream.WriteBuffer(FData.account, SizeOf(FData.account));
  Stream.WriteBuffer(FData.n_operation, SizeOf(FData.n_operation));
  Stream.WriteBuffer(FData.fee, SizeOf(FData.fee));
  Result := True;
end;

function TOpRecoverFunds.SenderAccount: Cardinal;
begin
  Result := FData.account;
end;

function TOpRecoverFunds.N_Operation: Cardinal;
begin
  Result := FData.n_operation;
end;

function TOpRecoverFunds.toString: String;
begin
  Result := Format('Recover founds of account %s fee:%s (n_op:%d)',[
    TAccountComp.AccountNumberToAccountTxtNumber(FData.account),
    TAccountComp.FormatMoney(FData.fee),fData.n_operation]);
end;

initialization
  RegisterOperationsClass;
end.

