{
  Copyright (c) 2016 by Albert Molina
  Copyright (c) 2017 by BlaiseCoin developers

  Distributed under the MIT software license, see the accompanying file LICENSE
  or visit http://www.opensource.org/licenses/mit-license.php.

  This unit is a part of BlaiseCoin, a P2P crypto-currency.
}

unit UAccounts;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface

uses
  Classes, UConst, UCrypto, SyncObjs, UThread;

Type
  TAccountKey = TECDSA_Public;
  PAccountKey = ^TAccountKey;

  TAccountComp = class
  private
  public
    class function IsValidAccountKey(account: TAccountKey; var errors : AnsiString): Boolean;
    class function GetECInfoTxt(Const EC_OpenSSL_NID: Word) : AnsiString;
    class procedure ValidsEC_OpenSSL_NID(list : TList);
    class function AccountKey2RawString(account: TAccountKey): AnsiString;
    class function RawString2Accountkey(rawaccstr: AnsiString): TAccountKey;
    class function privateToAccountkey(key: TECPrivateKey): TAccountKey;
    class function IsAccountBlockedByProtocol(account_number, blocks_count : Cardinal) : Boolean;
    class function Equal(account1,account2 : TAccountKey) : Boolean;
    class function AccountNumberToAccountTxtNumber(account_number : Cardinal) : AnsiString;
    class function AccountTxtNumberToAccountNumber(Const account_txt_number : AnsiString; var account_number : Cardinal) : Boolean;
    class function FormatMoney(Money : Int64) : AnsiString;
    class function TxtToMoney(Const moneytxt : AnsiString; var money : Int64) : Boolean;
    class function AccountKeyToExport(Const account : TAccountKey) : AnsiString;
    class function AccountKeyFromImport(Const HumanReadable : AnsiString; var account : TAccountKey; var errors : AnsiString) : Boolean;
    class function AccountPublicKeyExport(Const account : TAccountKey) : AnsiString;
    class function AccountPublicKeyImport(Const HumanReadable : AnsiString; var account : TAccountKey; var errors : AnsiString) : Boolean;
    class function AccountBlock(Const account_number : Cardinal) : Cardinal;
  end;

  TAccount = record
    account: Cardinal;        // FIXED value. Account number
    accountkey: TAccountKey;  // Public EC
    balance: UInt64;          // Balance, always >= 0
    updated_block: Cardinal;  // Number of block where was updated
    n_operation: Cardinal;    // count number of owner operations (when receive, this is not updated)
    //
    previous_updated_block : Cardinal; // New Build 1.0.8 -> Only used to store this info to storage. It helps App to search when an account was updated. NOT USED FOR HASH CALCULATIONS!
  end;
  PAccount = ^TAccount;

  TBlockAccount = record
    blockaccount : Cardinal;  // FIXED. Number in the BlockChain
    accounts : array[0..CT_AccountsPerBlock-1] of TAccount;
    timestamp: Cardinal;      // FIXED: Same value that stored in BlockChain. Included here because I need it to calculate new target value
    block_hash: AnsiString;   // Calculated on every block change (on create and on accounts updated)
    // New Build 1.0.8 "target" stored in TBlockAccount to increase performance calculating network hash rate.
    target: Cardinal;         // FIXED: Same value that stored in BlockChain. ** NOT USED TO CALC BLOCK HASHING **
    // New Build 1.5
    AccumulatedWork : UInt64; // FIXED: Accumulated work (previous + target) ** NOT USED TO CALC BLOCK HASHING and NOT STORED **
  end;
  PBlockAccount = ^TBlockAccount;

  { Estimated TAccount size:
    4 + 200 (max aprox) + 8 + 4 + 4 = 220 max aprox
    Estimated TBlockAccount size:
    4 + (5 * 220) + 4 + 32 = 1140 max aprox
  }

  TOrderedCardinalList = class
  private
    FOrderedList : TList;
    FDisabledsCount : Integer;
    FModifiedWhileDisabled : Boolean;
    FOnListChanged: TNotifyEvent;
    procedure NotifyChanged;
  public
    constructor Create;
    destructor Destroy; override;
    function Add(Value : Cardinal) : Integer;
    procedure Remove(Value : Cardinal);
    procedure Clear;
    function Get(index : Integer) : Cardinal;
    function Count : Integer;
    function Find(const Value: Cardinal; var Index: Integer): Boolean;
    procedure Disable;
    procedure Enable;
    property OnListChanged : TNotifyEvent read FOnListChanged write FOnListChanged;
    procedure CopyFrom(Sender : TOrderedCardinalList);
  end;

  TPCSafeBox = class;

  // This is a class to quickly find accountkeys and their respective account number/s
  TOrderedAccountKeysList = class
  private
    FAutoAddAll : Boolean;
    FAccountList : TPCSafeBox;
    FOrderedAccountKeysList : TList; // An ordered list of pointers to quickly find account keys in account list
    function Find(Const AccountKey: TAccountKey; var Index: Integer): Boolean;
    function GetAccountKeyList(index: Integer): TOrderedCardinalList;
    function GetAccountKey(index: Integer): TAccountKey;
  protected
    procedure ClearAccounts(RemoveAccountList : Boolean);
  public
    constructor Create(AccountList : TPCSafeBox; AutoAddAll : Boolean);
    destructor Destroy; override;
    procedure AddAccountKey(Const AccountKey : TAccountKey);
    procedure RemoveAccountKey(Const AccountKey : TAccountKey);
    procedure AddAccounts(Const AccountKey : TAccountKey; const accounts : array of Cardinal);
    procedure RemoveAccounts(Const AccountKey : TAccountKey; const accounts : array of Cardinal);
    function IndexOfAccountKey(Const AccountKey : TAccountKey) : Integer;
    property AccountKeyList[index : Integer] : TOrderedCardinalList read GetAccountKeyList;
    property AccountKey[index : Integer] : TAccountKey read GetAccountKey;
    function Count : Integer;
    property SafeBox : TPCSafeBox read FAccountList;
    procedure Clear;
  end;


  // SafeBox is a box that only can be updated using SafeBoxTransaction, and this
  // happens only when a new BlockChain is included. After this, a new "SafeBoxHash"
  // is created, so each SafeBox has a unique SafeBoxHash

  { TPCSafeBox }

  TPCSafeBox = class
  private
    FBlockAccountsList : TList;
    FListOfOrderedAccountKeysList : TList;
    FBufferBlocksHash: TRawBytes;
    FTotalBalance: Int64;
    FTotalFee: Int64;
    FSafeBoxHash : TRawBytes;
    FLock: TPCCriticalSection; // Thread safe
    FPreviousBlockSafeBoxHash : TRawBytes;
    FWorkSum : UInt64;
    procedure SetAccount(account_number : Cardinal; newAccountkey: TAccountKey; newBalance: UInt64; newN_operation: Cardinal);
    procedure AccountKeyListAddAccounts(Const AccountKey : TAccountKey; const accounts : array of Cardinal);
    procedure AccountKeyListRemoveAccount(Const AccountKey : TAccountKey; const accounts : array of Cardinal);
  protected
    function AddNew(Const accountkey: TAccountKey; reward: UInt64; timestamp: Cardinal; compact_target: Cardinal; Const proof_of_work: AnsiString) : TBlockAccount;
  public
    constructor Create;
    destructor Destroy; override;
    function AccountsCount: Integer;
    function BlocksCount : Integer;
    procedure CopyFrom(accounts : TPCSafeBox);
    class function CalcBlockHash(const block : TBlockAccount):AnsiString;
    class function BlockAccountToText(Const block : TBlockAccount):AnsiString;
    function LoadSafeBoxFromStream(Stream : TStream; var LastReadBlock : TBlockAccount; var errors : AnsiString) : Boolean;
    class function LoadSafeBoxStreamHeader(Stream : TStream; var BlocksCount : Cardinal) : Boolean;
    procedure SaveSafeBoxToAStream(Stream : TStream);
    procedure Clear;
    function Account(account_number : Cardinal) : TAccount;
    function Block(block_number : Cardinal) : TBlockAccount;
    function CalcSafeBoxHash : TRawBytes;
    function CalcBlockHashRateInKhs(block_number : Cardinal; Previous_blocks_average : Cardinal) : Int64;
    property TotalBalance : Int64 read FTotalBalance;
    procedure StartThreadSafe;
    procedure EndThreadSafe;
    property SafeBoxHash : TRawBytes read FSafeBoxHash;
    property PreviousBlockSafeBoxHash : TRawBytes read FPreviousBlockSafeBoxHash;
    property WorkSum : UInt64 read FWorkSum; // New Build 1.5
  end;


  TOrderedAccountList = class
  private
    FList : TList;
    function Find(const account_number: Cardinal; var Index: Integer): Boolean;
  public
    constructor Create;
    destructor Destroy; Override;
    procedure Clear;
    function Add(Const account : TAccount) : Integer;
    function Count : Integer;
    function Get(index : Integer) : TAccount;
  end;


  TPCSafeBoxTransaction = class
  private
    FOrderedList : TOrderedAccountList;
    FFreezedAccounts : TPCSafeBox;
    FTotalBalance: Int64;
    FTotalFee: Int64;
    FOldSafeBoxHash : TRawBytes;
    function GetInternalAccount(account_number : Cardinal) : PAccount;
  protected
  public
    constructor Create(SafeBox : TPCSafeBox);
    destructor Destroy; override;
    function TransferAmount(sender,target : Cardinal; n_operation : Cardinal; amount, fee : UInt64; var errors : AnsiString) : Boolean;
    function UpdateAccountkey(account_number, n_operation: Cardinal; accountkey: TAccountKey; fee: UInt64; var errors : AnsiString) : Boolean;
    function Commit(accountkey: TAccountKey; reward: UInt64; timestamp: Cardinal; compact_target: Cardinal; proof_of_work: AnsiString; var errors : AnsiString) : Boolean;
    function Account(account_number : Cardinal) : TAccount;
    procedure Rollback;
    function CheckIntegrity : Boolean;
    property FreezedSafeBox : TPCSafeBox read FFreezedAccounts;
    property TotalFee : Int64 read FTotalFee;
    property TotalBalance : Int64 read FTotalBalance;
    procedure CopyFrom(transaction : TPCSafeBoxTransaction);
    procedure CleanTransaction;
    function ModifiedCount : Integer;
    function Modified(index : Integer) : TAccount;
  end;

Const
  CT_Account_NUL : TAccount = (account:0;accountkey:(EC_OpenSSL_NID:0;x:'';y:'');balance:0;updated_block:0;n_operation:0;previous_updated_block:0);
  CT_BlockAccount_NUL : TBlockAccount = (
    blockaccount:0;
    accounts:(
    (account:0;accountkey:(EC_OpenSSL_NID:0;x:'';y:'');balance:0;updated_block:0;n_operation:0;previous_updated_block:0),
    (account:0;accountkey:(EC_OpenSSL_NID:0;x:'';y:'');balance:0;updated_block:0;n_operation:0;previous_updated_block:0),
    (account:0;accountkey:(EC_OpenSSL_NID:0;x:'';y:'');balance:0;updated_block:0;n_operation:0;previous_updated_block:0),
    (account:0;accountkey:(EC_OpenSSL_NID:0;x:'';y:'');balance:0;updated_block:0;n_operation:0;previous_updated_block:0),
    (account:0;accountkey:(EC_OpenSSL_NID:0;x:'';y:'');balance:0;updated_block:0;n_operation:0;previous_updated_block:0)
    );
    timestamp:0;
    block_hash:'';
    target:0;
    AccumulatedWork:0);

implementation

uses
  SysUtils, ULog, UStreamOp, UOpenSSLdef, UOpenSSL;

{ TAccountComp }

const
  CT_Base58 : AnsiString = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

class function TAccountComp.AccountKeyToExport(const account: TAccountKey): AnsiString;
var
  raw : TRawBytes;
  BN, BNMod, BNDiv : TBigNum;
begin
  Result := '';
  raw := AccountKey2RawString(account);
  BN := TBigNum.Create;
  BNMod := TBigNum.Create;
  BNDiv := TBigNum.Create(Length(CT_Base58));
  try
    BN.HexaValue :=
      '01' + TCrypto.ToHexaString(raw) +
      TCrypto.ToHexaString(Copy(TCrypto.DoSha256(raw), 1, 4));
    while (not BN.IsZero) do
    begin
      BN.Divide(BNDiv,BNMod);
      if (BNMod.Value >= 0) and (BNMod.Value < length(CT_Base58)) then
        Result := CT_Base58[Byte(BNMod.Value) + 1] + Result
      else
        raise Exception.Create('Error converting to Base 58');
    end;
  finally
    BN.Free;
    BNMod.Free;
    BNDiv.Free;
  end;
end;

class function TAccountComp.AccountBlock(const account_number: Cardinal): Cardinal;
begin
  Result := account_number div CT_AccountsPerBlock;
end;

class function TAccountComp.AccountKey2RawString(account: TAccountKey): AnsiString;
var s : TMemoryStream;
begin
  s := TMemoryStream.Create;
  try
    s.WriteBuffer(account.EC_OpenSSL_NID, SizeOf(account.EC_OpenSSL_NID));
    TStreamOp.WriteAnsiString(s, account.x);
    TStreamOp.WriteAnsiString(s, account.y);
    SetLength(Result, s.Size);
    s.Position := 0;
    s.Read(Result[1], s.Size);
  finally
    s.Free;
  end;
end;

class function TAccountComp.AccountKeyFromImport(const HumanReadable: AnsiString; var account: TAccountKey; var errors : AnsiString): Boolean;
var
  raw : TRawBytes;
  BN, BNAux, BNBase : TBigNum;
  i,j : Integer;
  s1,s2 : AnsiString;
begin
  result := False;
  account := CT_Account_NUL.accountkey;
  if length(HumanReadable) < 20 then
  begin
    errors := 'Invalid length';
    exit;
  end;
  BN := TBigNum.Create(0);
  BNAux := TBigNum.Create;
  BNBase := TBigNum.Create(1);
  try
    for i := length(HumanReadable) downto 1 do begin
      if (HumanReadable[i]<>' ') then
      begin
        j := pos(HumanReadable[i],CT_Base58);
        if j = 0 then
        begin
          errors := 'Invalid char "'+HumanReadable[i]+'" at pos '+inttostr(i)+'/'+inttostr(length(HumanReadable));
          exit;
        end;
        BNAux.Value := j-1;
        BNAux.Multiply(BNBase);
        BN.Add(BNAux);
        BNBase.Multiply(length(CT_Base58));
      end;
    end;
    // Last 8 hexa chars are the checksum of others
    s1 := Copy(BN.HexaValue, 3, length(BN.HexaValue));
    s2 := copy(s1, length(s1) - 7, 8);
    s1 := copy(s1, 1, length(s1) - 8);
    raw := TCrypto.HexaToRaw(s1);
    s1 := TCrypto.ToHexaString(TCrypto.DoSha256(raw));
    if copy(s1, 1, 8) <> s2 then
    begin
      // Invalid checksum
      errors := 'Invalid checksum';
      exit;
    end;
    try
      account := TAccountComp.RawString2Accountkey(raw);
      Result := True;
      errors := '';
    except
      // Nothing to do... invalid
      errors := 'Error on conversion from Raw to Account key';
    end;
  finally
    BN.Free;
    BNBase.Free;
    BNAux.Free;
  end;
end;

class function TAccountComp.AccountNumberToAccountTxtNumber(account_number: Cardinal): AnsiString;
var an : int64;
begin
  an := account_number;
  an := ((an * 101) mod 89) + 10;
  Result := IntToStr(account_number) + '-' + Inttostr(an);
end;

class function TAccountComp.AccountPublicKeyExport(const account: TAccountKey): AnsiString;
var raw : TRawBytes;
  BN, BNMod, BNDiv : TBigNum;
begin
  Result := '';
  raw := AccountKey2RawString(account);
  BN := TBigNum.Create;
  BNMod := TBigNum.Create;
  BNDiv := TBigNum.Create(Length(CT_Base58));
  try
    BN.HexaValue := '01'+TCrypto.ToHexaString( raw )+TCrypto.ToHexaString(Copy(TCrypto.DoSha256(raw),1,4));
    while (not BN.IsZero) do
    begin
      BN.Divide(BNDiv,BNMod);
      if (BNMod.Value>=0) and (BNMod.Value<length(CT_Base58)) then
        Result := CT_Base58[Byte(BNMod.Value)+1] + Result
      else
        raise Exception.Create('Error converting to Base 58');
    end;
  finally
    BN.Free;
    BNMod.Free;
    BNDiv.Free;
  end;
end;

class function TAccountComp.AccountPublicKeyImport(
  const HumanReadable: AnsiString; var account: TAccountKey;
  var errors: AnsiString): Boolean;
var raw : TRawBytes;
  BN, BNAux, BNBase : TBigNum;
  i,j : Integer;
  s1,s2 : AnsiString;
begin
  result := False;
  errors := 'Invalid length';
  account := CT_Account_NUL.accountkey;
  if length(HumanReadable)<20 then exit;
  BN := TBigNum.Create(0);
  BNAux := TBigNum.Create;
  BNBase := TBigNum.Create(1);
  try
    for i := length(HumanReadable) downto 1 do
    begin
      j := pos(HumanReadable[i],CT_Base58);
      if j=0 then
      begin
        errors := 'Invalid char "'+HumanReadable[i]+'" at pos '+inttostr(i)+'/'+inttostr(length(HumanReadable));
        exit;
      end;
      BNAux.Value := j-1;
      BNAux.Multiply(BNBase);
      BN.Add(BNAux);
      BNBase.Multiply(length(CT_Base58));
    end;
    // Last 8 hexa chars are the checksum of others
    s1 := Copy(BN.HexaValue,3,length(BN.HexaValue));
    s2 := copy(s1,length(s1)-7,8);
    s1 := copy(s1,1,length(s1)-8);
    raw := TCrypto.HexaToRaw(s1);
    s1 := TCrypto.ToHexaString( TCrypto.DoSha256(raw) );
    if copy(s1,1,8)<>s2 then
    begin
      // Invalid checksum
      errors := 'Invalid checksum';
      exit;
    end;
    try
      account := TAccountComp.RawString2Accountkey(raw);
      Result := True;
      errors := '';
    except
      // Nothing to do... invalid
      errors := 'Error on conversion from Raw to Account key';
    end;
  finally
    BN.Free;
    BNBase.Free;
    BNAux.Free;
  end;
end;

class function TAccountComp.AccountTxtNumberToAccountNumber(const account_txt_number: AnsiString; var account_number: Cardinal): Boolean;
var
  i : Integer;
  an,rn,anaux : Int64;
begin
  Result := False;
  if length(trim(account_txt_number))=0 then exit;
  an := 0;
  i := 1;
  while (i<=length(account_txt_number)) do
  begin
    if account_txt_number[i] in ['0'..'9'] then
    begin
      an := (an * 10) + ord( account_txt_number[i] ) - ord('0');
    end
    else
      break;
    inc(i);
  end;
  account_number := an;
  if (i>length(account_txt_number)) then
  begin
    result := True;
    exit;
  end;
  if (account_txt_number[i] in ['-','.',' ']) then
    inc(i);
  if length(account_txt_number)-1<>i then
    exit;
  rn := StrToIntDef(copy(account_txt_number,i,length(account_txt_number)),0);
  anaux := ((an * 101) mod 89) + 10;
  Result := rn = anaux;
end;

class function TAccountComp.Equal(account1, account2: TAccountKey): Boolean;
begin
  Result := (account1.EC_OpenSSL_NID=account2.EC_OpenSSL_NID) and
    (account1.x=account2.x) and (account1.y=account2.y);
end;

class function TAccountComp.FormatMoney(Money: Int64): AnsiString;
begin
  Result := FormatFloat('#,###0.0000',(Money/10000));
end;

class function TAccountComp.GetECInfoTxt(const EC_OpenSSL_NID: Word): AnsiString;
begin
  case EC_OpenSSL_NID of
    NID_secp256k1 : Result := 'secp256k1';
    NID_secp384r1 : Result := 'secp384r1';
    NID_sect283k1 : Result := 'secp283k1';
    NID_secp521r1 : Result := 'secp521r1';
  else
    Result := '(Unknown ID:'+inttostr(EC_OpenSSL_NID)+')';
  end;
end;

class function TAccountComp.IsAccountBlockedByProtocol(account_number, blocks_count: Cardinal): Boolean;
begin
  if blocks_count<CT_WaitNewBlocksBeforeTransaction then
    result := True
  else
    Result := ((blocks_count-CT_WaitNewBlocksBeforeTransaction) * CT_AccountsPerBlock) <= account_number;
end;

class function TAccountComp.IsValidAccountKey(account: TAccountKey; var errors : AnsiString): Boolean;
begin
  errors := '';
  case account.EC_OpenSSL_NID of
    NID_secp256k1,
    NID_secp384r1,
    NID_sect283k1,
    NID_secp521r1 :
    begin
      Result := TECPrivateKey.IsValidPublicKey(account);
      if not Result then
      begin
        errors := Format('Invalid AccountKey type:%d - Length x:%d y:%d Error:%s',[account.EC_OpenSSL_NID,length(account.x),length(account.y),  ERR_error_string(ERR_get_error(),nil)]);
      end;
    end;
  else
    errors := Format('Invalid AccountKey type:%d (Unknown type) - Length x:%d y:%d',[account.EC_OpenSSL_NID,length(account.x),length(account.y)]);
    Result := False;
  end;
  if (errors='') and (not Result) then
    errors := ERR_error_string(ERR_get_error(),nil);
end;

class function TAccountComp.PrivateToAccountkey(key: TECPrivateKey): TAccountKey;
begin
  Result := key.PublicKey;
end;

class function TAccountComp.RawString2Accountkey(rawaccstr: AnsiString): TAccountKey;
var s : TMemoryStream;
begin
  Result := CT_TECDSA_Public_Nul;
  s := TMemoryStream.Create;
  try
    s.WriteBuffer(rawaccstr[1],length(rawaccstr));
    s.Position := 0;
    s.Read(Result.EC_OpenSSL_NID,SizeOf(Result.EC_OpenSSL_NID));
    if (TStreamOp.ReadAnsiString(s,Result.x)<=0) then
    begin
      Result := CT_TECDSA_Public_Nul;
      exit;
    end;
    if (TStreamOp.ReadAnsiString(s,Result.y)<=0) then
    begin
      Result := CT_TECDSA_Public_Nul;
      exit;
    end;
  finally
    s.Free;
  end;
end;

class function TAccountComp.TxtToMoney(const moneytxt : AnsiString; var money : Int64) : Boolean;
var s : AnsiString;
begin
  money := 0;
  if Trim(moneytxt)='' then
  begin
    Result := True;
    exit;
  end;
  try
    s := StringReplace(moneytxt,ThousandSeparator,'',[rfReplaceAll]);
    money := Round( StrToFloat(s)*10000 );
    Result := True;
  except
    result := False;
  end;
end;

class procedure TAccountComp.ValidsEC_OpenSSL_NID(list: TList);
begin
  list.Clear;
  list.Add(TObject(NID_secp256k1)); // = 714
  list.Add(TObject(NID_secp384r1)); // = 715
  list.Add(TObject(NID_sect283k1)); // = 729
  list.Add(TObject(NID_secp521r1)); // = 716
end;

{ TPCSafeBox }

constructor TPCSafeBox.Create;
begin
  FLock := TPCCriticalSection.Create('TPCSafeBox_Lock');
  FBlockAccountsList := TList.Create;
  FListOfOrderedAccountKeysList := TList.Create;
  Clear;
end;

destructor TPCSafeBox.Destroy;
var i : Integer;
begin
  Clear;
  for i := 0 to FListOfOrderedAccountKeysList.Count - 1 do
  begin
    TOrderedAccountKeysList( FListOfOrderedAccountKeysList[i] ).FAccountList := nil;
  end;
  FreeAndNil(FBlockAccountsList);
  FreeAndNil(FListOfOrderedAccountKeysList);
  FreeAndNil(FLock);
  inherited;
end;

procedure TPCSafeBox.Clear;
var i : Integer;
  P : PBlockAccount;
begin
  StartThreadSafe;
  try
    for i := 0 to FBlockAccountsList.Count - 1 do
    begin
      P := FBlockAccountsList.Items[i];
      Dispose(P);
    end;
    FBlockAccountsList.Clear;
    for i:=0 to FListOfOrderedAccountKeysList.count-1 do
    begin
      TOrderedAccountKeysList( FListOfOrderedAccountKeysList[i] ).ClearAccounts(False);
    end;
    FBufferBlocksHash := '';
    FTotalBalance := 0;
    FTotalFee := 0;
    FSafeBoxHash := CalcSafeBoxHash;
    FPreviousBlockSafeBoxHash := '';
    FWorkSum := 0;
  finally
    EndThreadSafe;
  end;
end;

procedure TPCSafeBox.CopyFrom(accounts: TPCSafeBox);
var i,j : Cardinal;
  P : PBlockAccount;
  BA : TBlockAccount;
begin
  StartThreadSafe;
  try
    accounts.StartThreadSafe;
    try
      if accounts=Self then
        exit;
      Clear;
      if accounts.BlocksCount>0 then
      begin
        for i := 0 to accounts.BlocksCount - 1 do
        begin
          BA := accounts.Block(i);
          New(P);
          P^ := BA;
          FBlockAccountsList.Add(P);
          for j := Low(BA.accounts) to High(BA.accounts) do
          begin
            AccountKeyListAddAccounts(BA.accounts[j].accountkey,[BA.accounts[j].account]);
          end;
        end;
      end;
      FTotalBalance := accounts.TotalBalance;
      FTotalFee := accounts.FTotalFee;
      FBufferBlocksHash := accounts.FBufferBlocksHash;
      FSafeBoxHash := accounts.FSafeBoxHash;
      FPreviousBlockSafeBoxHash := accounts.FPreviousBlockSafeBoxHash;
      FWorkSum := accounts.FWorkSum;
    finally
      accounts.EndThreadSafe;
    end;
  finally
    EndThreadSafe;
  end;
end;

procedure TPCSafeBox.StartThreadSafe;
begin
  TPCThread.ProtectEnterCriticalSection(Self,FLock);
end;

procedure TPCSafeBox.EndThreadSafe;
begin
  FLock.Release;
end;

function TPCSafeBox.Account(account_number: Cardinal): TAccount;
var b : Cardinal;
begin
  b := account_number div CT_AccountsPerBlock;
  if (b<0) or (b>=FBlockAccountsList.Count) then
    raise Exception.Create('Invalid account: '+IntToStr(account_number));
  Result := PBlockAccount(FBlockAccountsList.Items[b])^.accounts[account_number mod CT_AccountsPerBlock];
end;

procedure TPCSafeBox.SetAccount(account_number : Cardinal; newAccountkey: TAccountKey; newBalance: UInt64; newN_operation: Cardinal);
var
  iBlock : Cardinal;
  i,j,iAccount : Integer;
  lastbalance : UInt64;
  P : PBlockAccount;
begin
  iBlock := account_number div CT_AccountsPerBlock;
  iAccount := account_number mod CT_AccountsPerBlock;
  P := FBlockAccountsList.Items[iBlock];
  if (not TAccountComp.Equal(P^.accounts[iAccount].accountkey,newAccountkey)) then
  begin
    AccountKeyListRemoveAccount(P^.accounts[iAccount].accountkey,[account_number]);
    AccountKeyListAddAccounts(newAccountkey,[account_number]);
  end;

  P^.accounts[iAccount].accountkey := newAccountkey;
  lastbalance := P^.accounts[iAccount].balance;
  P^.accounts[iAccount].balance := newBalance;
  P^.accounts[iAccount].previous_updated_block := P^.accounts[iAccount].updated_block;
  P^.accounts[iAccount].updated_block := BlocksCount;
  P^.accounts[iAccount].n_operation := newN_operation;
  P^.block_hash := CalcBlockHash(P^);
  j := (length(P^.block_hash)*(iBlock));
  for i := 1 to length(P^.block_hash) do
  begin
    FBufferBlocksHash[i+j] := P^.block_hash[i];
  end;

  FTotalBalance := FTotalBalance - (Int64(lastbalance)-Int64(newBalance));
  FTotalFee := FTotalFee + (Int64(lastbalance)-Int64(newBalance));
end;

function TPCSafeBox.AddNew(const accountkey: TAccountKey; reward: UInt64;
  timestamp: Cardinal; compact_target: Cardinal; const proof_of_work: AnsiString
  ): TBlockAccount;
var i, base_addr : Integer;
  P : PBlockAccount;
  accs : array of cardinal;
begin
  base_addr := BlocksCount * CT_AccountsPerBlock;
  Result := CT_BlockAccount_NUL;
  Result.blockaccount := BlocksCount;
  setlength(accs,length(Result.accounts));
  for i := Low(Result.accounts) to High(Result.accounts) do
  begin
    Result.accounts[i] := CT_Account_NUL;
    Result.accounts[i].account := base_addr + i;
    Result.accounts[i].accountkey := accountkey;
    Result.accounts[i].updated_block := BlocksCount;
    Result.accounts[i].n_operation := 0;
    if i=0 then
    begin
      // Only first account wins the reward + fee
      Result.accounts[i].balance := reward + FTotalFee;
    end else
    begin
    end;
    accs[i] := base_addr + i;
  end;
  Result.timestamp := timestamp;
  Result.block_hash := CalcBlockHash(Result);
  Result.target := compact_target;
  Inc(FWorkSum,Result.target);
  Result.AccumulatedWork := FWorkSum;

  New(P);
  P^ := Result;
  FBlockAccountsList.Add(P);
  FBufferBlocksHash := FBufferBlocksHash+Result.block_hash;
  Inc(FTotalBalance,reward + FTotalFee);
  Dec(FTotalFee,FTotalFee);
  AccountKeyListAddAccounts(accountkey,accs);
  // Calculating new value of safebox
  FPreviousBlockSafeBoxHash := FSafeBoxHash;
  FSafeBoxHash := CalcSafeBoxHash;
end;

procedure TPCSafeBox.AccountKeyListAddAccounts(const AccountKey: TAccountKey; const accounts: array of Cardinal);
var i : Integer;
begin
  for i := 0 to FListOfOrderedAccountKeysList.count-1 do
  begin
    TOrderedAccountKeysList( FListOfOrderedAccountKeysList[i] ).AddAccounts(AccountKey,accounts);
  end;
end;

procedure TPCSafeBox.AccountKeyListRemoveAccount(const AccountKey: TAccountKey; const accounts: array of Cardinal);
var i : Integer;
begin
  for i := 0 to FListOfOrderedAccountKeysList.count-1 do
  begin
    TOrderedAccountKeysList( FListOfOrderedAccountKeysList[i] ).RemoveAccounts(AccountKey,accounts);
  end;
end;

function TPCSafeBox.AccountsCount: Integer;
begin
  Result := BlocksCount * CT_AccountsPerBlock;
end;

function TPCSafeBox.Block(block_number: Cardinal): TBlockAccount;
begin
  if (block_number<0) or (block_number>=FBlockAccountsList.Count) then
    raise Exception.Create('Invalid block number: '+inttostr(block_number));
  Result := PBlockAccount(FBlockAccountsList.Items[block_number])^;
end;

class function TPCSafeBox.BlockAccountToText(const block: TBlockAccount): AnsiString;
begin
  Result := Format('Block:%d Timestamp:%d BlockHash:%s',
    [block.blockaccount, block.timestamp,
     TCrypto.ToHexaString(block.block_hash)]);
end;

function TPCSafeBox.BlocksCount: Integer;
begin
  Result := FBlockAccountsList.Count;
end;

class function TPCSafeBox.CalcBlockHash(const block : TBlockAccount): AnsiString;
var
  s : AnsiString;
  ms : TMemoryStream;
  i : Integer;
  l : LongInt;
begin
  ms := TMemoryStream.Create;
  try
    ms.WriteBuffer(block.blockaccount, 4); // Little endian
    for i := Low(block.accounts) to High(block.accounts) do
    begin
      ms.WriteBuffer(block.accounts[i].account, 4);  // Little endian
      s := TAccountComp.AccountKey2RawString(block.accounts[i].accountkey);
      l := Length(s);
      if l > 0 then
        ms.WriteBuffer(s[1], l); // Raw bytes
      ms.Write(block.accounts[i].balance, SizeOf(Uint64));  // Little endian
      ms.Write(block.accounts[i].updated_block, 4);  // Little endian
      ms.Write(block.accounts[i].n_operation, 4); // Little endian
    end;
    ms.Write(block.timestamp, 4); // Little endian
    Result := TCrypto.DoSha256(ms.Memory, ms.Size);
  finally
    ms.Free;
  end;
end;

function TPCSafeBox.CalcBlockHashRateInKhs(block_number: Cardinal;
  Previous_blocks_average: Cardinal): Int64;
var c,t : Cardinal;
  t_sum : Extended;
  bn, bn_sum : TBigNum;
begin
  FLock.Acquire;
  try
    bn_sum := TBigNum.Create;
    try
      if (block_number=0) then
      begin
        Result := 1;
        exit;
      end;
      if (block_number<0) or (block_number>=FBlockAccountsList.Count) then
        raise Exception.Create('Invalid block number: '+inttostr(block_number));
      if (Previous_blocks_average<=0) then
        raise Exception.Create('Dev error 20161016-1');
      if (Previous_blocks_average>block_number) then
        Previous_blocks_average := block_number;
      //
      c := (block_number - Previous_blocks_average)+1;
      t_sum := 0;
      while (c<=block_number) do
      begin
        bn := TBigNum.TargetToHashRate(PBlockAccount(FBlockAccountsList.Items[c])^.target);
        try
          bn_sum.Add(bn);
        finally
          bn.Free;
        end;
        t_sum := t_sum + (PBlockAccount(FBlockAccountsList.Items[c])^.timestamp - PBlockAccount(FBlockAccountsList.Items[c-1])^.timestamp);
        inc(c);
      end;
      bn_sum.Divide(Previous_blocks_average); // Obtain target average
      t_sum := t_sum / Previous_blocks_average; // time average
      t := Round(t_sum);
      if (t<>0) then
      begin
        bn_sum.Divide(t);
      end;
      Result := bn_sum.Divide(1024).Value; // Value in Kh/s
    finally
      bn_sum.Free;
    end;
  finally
    FLock.Release;
  end;
end;

function TPCSafeBox.CalcSafeBoxHash: TRawBytes;
begin
  // if No buffer to hash is because it's firts block... so use Genesis: CT_Genesis_Magic_String_For_Old_Block_Hash
  if FBufferBlocksHash = '' then
    Result := TCrypto.DoSha256(CT_Genesis_Magic_String_For_Old_Block_Hash)
  else
    Result := TCrypto.DoSha256(FBufferBlocksHash);
end;

function TPCSafeBox.LoadSafeBoxFromStream(Stream : TStream; var LastReadBlock : TBlockAccount; var errors : AnsiString) : Boolean;
var
  w : Word;
  blockscount,iblock,iacc : Cardinal;
  s : AnsiString;
  block : TBlockAccount;
  P : PBlockAccount;
  j : Integer;
  safeBoxBankVersion : Word;
begin
  StartThreadSafe;
  try
    Clear;
    Result := False;
    try
      errors := 'Invalid stream';
      TStreamOp.ReadAnsiString(Stream,s);
      if s <> CT_MagicIdentificator then
        exit;
      errors := 'Invalid version or corrupted stream';
      if Stream.Size < 8 then
        exit;
      Stream.ReadBuffer(w, 2);
      if w <> CT_BlockChain_Protocol_Version then
        exit;
      Stream.ReadBuffer(safeBoxBankVersion, 2);
      if safeBoxBankVersion <> CT_SafeBoxBankVersion then
      begin
        errors := 'Invalid SafeBoxBank version: '+InttostR(safeBoxBankVersion);
        exit;
      end;
      Stream.ReadBuffer(blockscount, 4);
      if blockscount > CT_NewLineSecondsAvg * 2000000 then
        exit; // Protection for corrupted data...
      // Build 1.3.0 to increase reading speed:
      FBlockAccountsList.Capacity := blockscount;
      errors := 'Corrupted stream';
      for iblock := 0 to blockscount - 1 do
      begin
        errors := 'Corrupted stream reading block '+inttostr(iblock+1)+'/'+inttostr(blockscount);
        block := CT_BlockAccount_NUL;
        if Stream.Read(block.blockaccount, 4) < 4 then
          exit;
        if block.blockaccount<>iblock then
          exit; // Invalid value
        for iacc := Low(block.accounts) to High(block.accounts) do
        begin
          errors := 'Corrupted stream reading account '+inttostr(iacc+1)+'/'+inttostr(length(block.accounts))+' of block '+inttostr(iblock+1)+'/'+inttostr(blockscount);
          if Stream.Read(block.accounts[iacc].account,4) < 4 then
            exit;
          if TStreamOp.ReadAnsiString(Stream,s)<0 then
            exit;
          block.accounts[iacc].accountkey := TAccountComp.RawString2Accountkey(s);
          if Stream.Read(block.accounts[iacc].balance, SizeOf(UInt64)) < SizeOf(UInt64) then
            exit;
          if Stream.Read(block.accounts[iacc].updated_block, 4) < 4 then
            exit;
          if Stream.Read(block.accounts[iacc].n_operation, 4) < 4 then
            exit;
          if safeBoxBankVersion >= 1 then
          begin
            if Stream.Read(block.accounts[iacc].previous_updated_block, 4) < 4 then
              exit;
          end;
          // check valid
          if not TAccountComp.IsValidAccountKey(block.accounts[iacc].accountkey, s) then
          begin
            errors := errors + ' > '+s;
            exit;
          end;
          inc(FTotalBalance,block.accounts[iacc].balance);
        end;
        errors := 'Corrupted stream reading block hash '+inttostr(iblock+1)+'/'+inttostr(blockscount);
        if Stream.Read(block.timestamp, 4) < 4 then
          exit;
        if TStreamOp.ReadAnsiString(Stream,s) < 0 then
          exit;
        block.block_hash := s;
        // Check is valid:
        if CalcBlockHash(block)<>block.block_hash then
          exit;
        if safeBoxBankVersion >= 2 then
        begin
          if Stream.Read(block.target, 4) < 4 then
            exit;
        end;
        Inc(FWorkSum,block.target);
        block.AccumulatedWork := FWorkSum;
        // Add
        New(P);
        P^ := block;
        FBlockAccountsList.Add(P);
        for j := low(block.accounts) to High(block.accounts) do
        begin
          AccountKeyListAddAccounts(block.accounts[j].accountkey,[block.accounts[j].account]);
        end;
        FBufferBlocksHash := FBufferBlocksHash+block.block_hash;
        LastReadBlock := block;
      end;
      // Build 1.3.0 adding previous block hash information
      TStreamOp.ReadAnsiString(Stream,FPreviousBlockSafeBoxHash);
      // Build 1.3.0 adding calculation
      FSafeBoxHash := CalcSafeBoxHash;
      Result := True;
    finally
      if not Result then
        Clear;
    end;
  finally
    EndThreadSafe;
  end;
end;

class function TPCSafeBox.LoadSafeBoxStreamHeader(Stream: TStream; var BlocksCount: Cardinal): Boolean;
var
  w : Word;
  s : AnsiString;
  safeBoxBankVersion : Word;
begin
  Result := False;
  TStreamOp.ReadAnsiString(Stream,s);
  if s <> CT_MagicIdentificator then
    exit;
  if Stream.Size < 8 then
    exit;
  Stream.Read(w, 2);
  if w <> CT_BlockChain_Protocol_Version then
    exit;
  Stream.Read(safeBoxBankVersion, 2);
  if safeBoxBankVersion <> CT_SafeBoxBankVersion then
    exit;
  Stream.Read(BlocksCount, 4);
  if BlocksCount > CT_NewLineSecondsAvg * 2000000 then
    exit; // Protection for corrupted data...
  Result := True;
end;

procedure TPCSafeBox.SaveSafeBoxToAStream(Stream: TStream);
Var
  c,iblock,iacc : Cardinal;
  b : TBlockAccount;
begin
  StartThreadSafe;
  try
    TStreamOp.WriteAnsiString(Stream, CT_MagicIdentificator);
    Stream.WriteBuffer(CT_BlockChain_Protocol_Version, SizeOf(CT_BlockChain_Protocol_Version));
    Stream.WriteBuffer(CT_SafeBoxBankVersion, SizeOf(CT_SafeBoxBankVersion));
    c := BlocksCount;
    Stream.WriteBuffer(c, Sizeof(c));
    for iblock := 0 to c - 1 do
    begin
      b := Block(iblock);
      Stream.WriteBuffer(b.blockaccount, SizeOf(b.blockaccount)); // Little endian
      for iacc := Low(b.accounts) to High(b.accounts) do
      begin
        Stream.WriteBuffer(b.accounts[iacc].account, Sizeof(b.accounts[iacc].account));
        TStreamOp.WriteAnsiString(Stream, TAccountComp.AccountKey2RawString(b.accounts[iacc].accountkey));
        Stream.WriteBuffer(b.accounts[iacc].balance, Sizeof(b.accounts[iacc].balance));
        Stream.WriteBuffer(b.accounts[iacc].updated_block, Sizeof(b.accounts[iacc].updated_block));
        Stream.WriteBuffer(b.accounts[iacc].n_operation, Sizeof(b.accounts[iacc].n_operation));
        Stream.WriteBuffer(b.accounts[iacc].previous_updated_block, Sizeof(b.accounts[iacc].previous_updated_block));
      end;
      Stream.WriteBuffer(b.timestamp, Sizeof(b.timestamp));
      TStreamOp.WriteAnsiString(Stream, b.block_hash);
      Stream.WriteBuffer(b.target, Sizeof(b.target));
    end;
    // New Build 1.3.0
    TStreamOp.WriteAnsiString(Stream, FPreviousBlockSafeBoxHash);
  finally
    EndThreadSafe;
  end;
end;

{ TPCSafeBoxTransaction }

constructor TPCSafeBoxTransaction.Create(SafeBox : TPCSafeBox);
begin
  FOrderedList := TOrderedAccountList.Create;
  FFreezedAccounts := SafeBox;
  FOldSafeBoxHash := SafeBox.FSafeBoxHash;
  FTotalBalance := FFreezedAccounts.FTotalBalance;
  FTotalFee := 0;
end;

destructor TPCSafeBoxTransaction.Destroy;
begin
  CleanTransaction;
  FreeAndNil(FOrderedList);
  inherited;
end;

function TPCSafeBoxTransaction.Account(account_number: Cardinal): TAccount;
var i :Integer;
begin
  if FOrderedList.Find(account_number,i) then
    Result := PAccount(FOrderedList.FList[i])^
  else
  begin
    Result := FreezedSafeBox.Account(account_number);
  end;
end;

function TPCSafeBoxTransaction.CheckIntegrity: Boolean;
begin
  Result := FOldSafeBoxHash = FFreezedAccounts.FSafeBoxHash;
end;

procedure TPCSafeBoxTransaction.CleanTransaction;
begin
  FOrderedList.Clear;
  FOldSafeBoxHash := FFreezedAccounts.FSafeBoxHash;
  FTotalBalance := FFreezedAccounts.FTotalBalance;
  FTotalFee := 0;
end;

function TPCSafeBoxTransaction.Commit(accountkey: TAccountKey; reward: UInt64; timestamp: Cardinal; compact_target: Cardinal; proof_of_work: AnsiString; var errors : AnsiString) : Boolean;
var
  i : Integer;
  B : TBlockAccount;
  Pa : PAccount;
begin
  Result := False;
  errors := '';
  FFreezedAccounts.StartThreadSafe;
  try
    if not CheckIntegrity then
    begin
      errors := 'Invalid integrity in accounts transaction on commit';
      exit;
    end;
    for i := 0 to FOrderedList.FList.Count - 1 do
    begin
      Pa := PAccount(FOrderedList.FList[i]);
      FFreezedAccounts.SetAccount(Pa^.account,
            Pa^.accountkey,
            Pa^.balance,
            Pa^.n_operation);
    end;
    //
    if (FFreezedAccounts.TotalBalance<>FTotalBalance) then
    begin
      TLog.NewLog(lterror,ClassName,Format('Invalid integrity balance! StrongBox:%d Transaction:%d',[FFreezedAccounts.TotalBalance,FTotalBalance]));
    end;
    if (FFreezedAccounts.FTotalFee<>FTotalFee) then
    begin
      TLog.NewLog(lterror,ClassName,Format('Invalid integrity fee! StrongBox:%d Transaction:%d',[FFreezedAccounts.FTotalFee,FTotalFee]));
    end;
    B := FFreezedAccounts.AddNew(accountkey,reward,timestamp,compact_target,proof_of_work);
    if (B.accounts[0].balance<>(reward + FTotalFee)) then
    begin
      TLog.NewLog(lterror,ClassName,Format('Invalid integrity reward! Account:%d Balance:%d  Reward:%d Fee:%d (Reward+Fee:%d)',
        [B.accounts[0].account,B.accounts[0].balance,reward,FTotalFee,reward+FTotalFee]));
    end;
    CleanTransaction;
    Result := True;
  finally
    FFreezedAccounts.EndThreadSafe;
  end;
end;

procedure TPCSafeBoxTransaction.CopyFrom(transaction : TPCSafeBoxTransaction);
var
  i : Integer;
  P : PAccount;
begin
  if transaction=Self then exit;
  if transaction.FFreezedAccounts<>FFreezedAccounts then raise Exception.Create('Invalid Freezed accounts to copy');
  CleanTransaction;
  for i := 0 to transaction.FOrderedList.FList.Count - 1 do
  begin
    P := PAccount(transaction.FOrderedList.FList[i]);
    FOrderedList.Add(P^);
  end;
  FOldSafeBoxHash := transaction.FOldSafeBoxHash;
  FTotalBalance := transaction.FTotalBalance;
  FTotalFee := transaction.FTotalFee;
end;

function TPCSafeBoxTransaction.GetInternalAccount(account_number: Cardinal): PAccount;
var i :Integer;
begin
  if FOrderedList.Find(account_number,i) then
    Result := PAccount(FOrderedList.FList[i])
  else
  begin
    i := FOrderedList.Add( FreezedSafeBox.Account(account_number) );
    Result := PAccount(FOrderedList.FList[i]);
  end;
end;

function TPCSafeBoxTransaction.Modified(index: Integer): TAccount;
begin
  Result := FOrderedList.Get(index);
end;

function TPCSafeBoxTransaction.ModifiedCount: Integer;
begin
  Result := FOrderedList.Count;
end;

procedure TPCSafeBoxTransaction.Rollback;
begin
  CleanTransaction;
end;

function TPCSafeBoxTransaction.TransferAmount(sender, target, n_operation : Cardinal; amount, fee: UInt64; var errors: AnsiString): Boolean;
var
  PaccSender, PaccTarget : PAccount;
begin
  Result := False;
  errors := '';
  if not CheckIntegrity then
  begin
    errors := 'Invalid integrity in accounts transaction';
    exit;
  end;
  if (sender<0) or (sender>=(FFreezedAccounts.BlocksCount*CT_AccountsPerBlock)) Or
     (target<0) or (target>=(FFreezedAccounts.BlocksCount*CT_AccountsPerBlock)) then
  begin
    errors := 'Invalid sender or target on transfer';
    exit;
  end;
  if TAccountComp.IsAccountBlockedByProtocol(sender,FFreezedAccounts.BlocksCount) then
  begin
    errors := 'Sender account is blocked for protocol';
    exit;
  end;
  if TAccountComp.IsAccountBlockedByProtocol(target,FFreezedAccounts.BlocksCount) then
  begin
    errors := 'Target account is blocked for protocol';
    exit;
  end;
  PaccSender := GetInternalAccount(sender);
  PaccTarget := GetInternalAccount(target);
  if (PaccSender^.n_operation+1<>n_operation) then
  begin
    errors := 'Incorrect n_operation';
    exit;
  end;
  if (PaccSender^.balance < (amount+fee)) then
  begin
    errors := 'Insuficient founds';
    exit;
  end;
  if ((PaccTarget^.balance + amount)>CT_MaxWalletAmount) then
  begin
    errors := 'Max account balance';
    exit;
  end;
  if (fee>CT_MaxTransactionFee) then
  begin
    errors := 'Max fee';
    exit;
  end;
  PaccSender^.previous_updated_block := PaccSender^.updated_block;
  PaccTarget^.previous_updated_block := PaccTarget.updated_block;
  PaccSender^.updated_block := FFreezedAccounts.BlocksCount;
  PaccTarget^.updated_block := FFreezedAccounts.BlocksCount;
  PaccSender^.n_operation := n_operation;
  PaccSender^.balance := PaccSender^.balance - (amount + fee);
  PaccTarget^.balance := PaccTarget^.balance + (amount);

  Dec(FTotalBalance,fee);
  inc(FTotalFee,fee);
  Result := True;
end;

function TPCSafeBoxTransaction.UpdateAccountkey(account_number, n_operation: Cardinal; accountkey: TAccountKey; fee: UInt64; var errors: AnsiString): Boolean;
var
  P : PAccount;
begin
  Result := False;
  errors := '';
  if (account_number<0) or (account_number>=(FFreezedAccounts.BlocksCount*CT_AccountsPerBlock)) then
  begin
    errors := 'Invalid account';
    exit;
  end;
  if (TAccountComp.IsAccountBlockedByProtocol(account_number,FFreezedAccounts.BlocksCount)) then
  begin
    errors := 'account is blocked for protocol';
    exit;
  end;
  P := GetInternalAccount(account_number);
  if (P^.n_operation+1<>n_operation) then
  begin
    errors := 'Incorrect n_operation';
    exit;
  end;
  if (P^.balance < fee) then
  begin
    errors := 'Insuficient founds';
    exit;
  end;
  P^.previous_updated_block := P^.updated_block;
  P^.updated_block := FFreezedAccounts.BlocksCount;
  P^.n_operation := n_operation;
  P^.accountkey := accountkey;
  Dec(P^.balance,fee);
  Dec(FTotalBalance,fee);
  Inc(FTotalFee,fee);
  Result := True;
end;

{ TOrderedAccountList }

constructor TOrderedAccountList.Create;
begin
  FList := TList.Create;
end;

destructor TOrderedAccountList.Destroy;
begin
  Clear;
  FreeAndNil(FList);
  inherited;
end;

function TOrderedAccountList.Add(const account: TAccount) : Integer;
var P : PAccount;
begin
  if Find(account.account,Result) then
  begin
    PAccount(FList[Result])^ := account;
  end
  else
  begin
    New(P);
    P^:=account;
    FList.Insert(Result,P);
  end;
end;

procedure TOrderedAccountList.Clear;
var
  i : Integer;
  P : PAccount;
begin
  for I := 0 to FList.Count - 1 do
  begin
    P := FList[i];
    Dispose(P);
  end;
  FList.Clear;
end;

function TOrderedAccountList.Count: Integer;
begin
  Result := FList.Count;
end;

function TOrderedAccountList.Find(const account_number: Cardinal; var Index: Integer): Boolean;
var
  L, H, I: Integer;
  C : Int64;
begin
  Result := False;
  L := 0;
  H := FList.Count - 1;
  while L <= H do
  begin
    I := (L + H) shr 1;
    C := Int64(PAccount(FList[I]).account) - Int64(account_number);
    if C < 0 then
      L := I + 1
    else
    begin
      H := I - 1;
      if C = 0 then
      begin
        Result := True;
        L := I;
      end;
    end;
  end;
  Index := L;
end;

function TOrderedAccountList.Get(index: Integer): TAccount;
begin
  Result := PAccount(FList.Items[index])^;
end;

{ TOrderedAccountKeysList }

Type
  TOrderedAccountKeyList = record
    rawaccountkey : TRawBytes;
    accounts_number : TOrderedCardinalList;
  end;
  POrderedAccountKeyList = ^TOrderedAccountKeyList;

function SortOrdered(Item1, Item2: Pointer): Integer;
begin
   Result := PtrInt(Item1) - PtrInt(Item2);
end;

constructor TOrderedAccountKeysList.Create(AccountList : TPCSafeBox; AutoAddAll : Boolean);
var i : Integer;
begin
  TLog.NewLog(ltdebug,Classname,'Creating an Ordered Account Keys List adding all:'+CT_TRUE_FALSE[AutoAddAll]);
  FAutoAddAll := AutoAddAll;
  FAccountList := AccountList;
  FOrderedAccountKeysList := TList.Create;
  if Assigned(AccountList) then
  begin
    AccountList.FListOfOrderedAccountKeysList.Add(Self);
    if AutoAddAll then
    begin
      for i := 0 to AccountList.AccountsCount - 1 do
      begin
        AddAccountKey(AccountList.Account(i).accountkey);
      end;
    end;
  end;
end;

destructor TOrderedAccountKeysList.Destroy;
begin
  TLog.NewLog(ltdebug,Classname,'Destroying an Ordered Account Keys List adding all:'+CT_TRUE_FALSE[FAutoAddAll]);
  if Assigned(FAccountList) then
  begin
    FAccountList.FListOfOrderedAccountKeysList.Remove(Self);
  end;
  ClearAccounts(True);
  FreeAndNil(FOrderedAccountKeysList);
  inherited;
end;

procedure TOrderedAccountKeysList.AddAccountKey(const AccountKey: TAccountKey);
var P : POrderedAccountKeyList;
  i,j : Integer;
begin
  if not Find(AccountKey,i) then
  begin
    New(P);
    P^.rawaccountkey := TAccountComp.AccountKey2RawString(AccountKey);
    P^.accounts_number := TOrderedCardinalList.Create;
    FOrderedAccountKeysList.Insert(i,P);
    // Search this key in the AccountsList and add all...
    j := 0;
    if Assigned(FAccountList) then
    begin
      for i:=0 to FAccountList.AccountsCount-1 do
      begin
        if TAccountComp.Equal(FAccountList.Account(i).accountkey,AccountKey) then
        begin
          // Note: P^.accounts will be ascending ordered due to "for i:=0 to ..."
          P^.accounts_number.Add(i);
        end;
      end;
      TLog.NewLog(ltdebug,Classname,Format('Adding account key (%d of %d) %s',[j,FAccountList.AccountsCount,TCrypto.ToHexaString(TAccountComp.AccountKey2RawString(AccountKey))]));
    end
    else
    begin
      TLog.NewLog(ltdebug,Classname,Format('Adding account key (no Account List) %s',[TCrypto.ToHexaString(TAccountComp.AccountKey2RawString(AccountKey))]));
    end;
  end;
end;

procedure TOrderedAccountKeysList.AddAccounts(const AccountKey: TAccountKey; const accounts: array of Cardinal);
var
  P : POrderedAccountKeyList;
  i : Integer;
begin
  if Find(AccountKey,i) then
  begin
    P := POrderedAccountKeyList(FOrderedAccountKeysList[i]);
  end
  else if (FAutoAddAll) then
  begin
    New(P);
    P^.rawaccountkey := TAccountComp.AccountKey2RawString(AccountKey);
    P^.accounts_number := TOrderedCardinalList.Create;
    FOrderedAccountKeysList.Insert(i,P);
  end
  else
    exit;
  for i := Low(accounts) to High(accounts) do
  begin
    P^.accounts_number.Add(accounts[i]);
  end;
end;

procedure TOrderedAccountKeysList.Clear;
begin
  ClearAccounts(True);
end;

procedure TOrderedAccountKeysList.ClearAccounts(RemoveAccountList : Boolean);
var
  P : POrderedAccountKeyList;
  i : Integer;
begin
  for i := 0 to FOrderedAccountKeysList.Count - 1 do
  begin
    P := FOrderedAccountKeysList[i];
    if RemoveAccountList then
    begin
      P^.accounts_number.Free;
      Dispose(P);
    end
    else
    begin
      P^.accounts_number.Clear;
    end;
  end;
  if RemoveAccountList then
  begin
    FOrderedAccountKeysList.Clear;
  end;
end;

function TOrderedAccountKeysList.Count: Integer;
begin
  Result := FOrderedAccountKeysList.Count;
end;

function TOrderedAccountKeysList.Find(const AccountKey: TAccountKey; var Index: Integer): Boolean;
var
  L, H, I, C: Integer;
  rak : TRawBytes;
begin
  Result := False;
  rak := TAccountComp.AccountKey2RawString(AccountKey);
  L := 0;
  H := FOrderedAccountKeysList.Count - 1;
  while L <= H do
  begin
    I := (L + H) shr 1;
    C := CompareStr( POrderedAccountKeyList(FOrderedAccountKeysList[I]).rawaccountkey, rak );
    if C < 0 then
      L := I + 1
    else
    begin
      H := I - 1;
      if C = 0 then
      begin
        Result := True;
        L := I;
      end;
    end;
  end;
  Index := L;
end;

function TOrderedAccountKeysList.GetAccountKey(index: Integer): TAccountKey;
var raw : TRawBytes;
begin
  raw := POrderedAccountKeyList(FOrderedAccountKeysList[index]).rawaccountkey;
  Result := TAccountComp.RawString2Accountkey(raw);
end;

function TOrderedAccountKeysList.GetAccountKeyList(index: Integer): TOrderedCardinalList;
begin
  Result := POrderedAccountKeyList(FOrderedAccountKeysList[index]).accounts_number;
end;

function TOrderedAccountKeysList.IndexOfAccountKey(const AccountKey: TAccountKey): Integer;
begin
  if not Find(AccountKey,Result) then
    Result := -1;
end;

procedure TOrderedAccountKeysList.RemoveAccounts(const AccountKey: TAccountKey; const accounts: array of Cardinal);
var
  P : POrderedAccountKeyList;
  i,j : Integer;
begin
  if not Find(AccountKey,i) then
    exit; // Nothing to do
  P :=  POrderedAccountKeyList(FOrderedAccountKeysList[i]);
  for j := Low(accounts) to High(accounts) do
  begin
    P^.accounts_number.Remove(accounts[j]);
  end;
  if (P^.accounts_number.Count=0) and (FAutoAddAll) then
  begin
    // Remove from list
    FOrderedAccountKeysList.Delete(i);
    // Free it
    P^.accounts_number.free;
    Dispose(P);
  end;
end;

procedure TOrderedAccountKeysList.RemoveAccountKey(const AccountKey: TAccountKey);
var
  P : POrderedAccountKeyList;
  i : Integer;
begin
  if not Find(AccountKey,i) then
    exit; // Nothing to do
  P :=  POrderedAccountKeyList(FOrderedAccountKeysList[i]);
  // Remove from list
  FOrderedAccountKeysList.Delete(i);
  // Free it
  P^.accounts_number.free;
  Dispose(P);
end;

{ TOrderedCardinalList }

constructor TOrderedCardinalList.Create;
begin
  FOrderedList := TList.Create;
  FDisabledsCount := 0;
  FModifiedWhileDisabled := False;
end;

destructor TOrderedCardinalList.Destroy;
begin
  FOrderedList.Free;
  inherited;
end;

procedure TOrderedCardinalList.Clear;
begin
  FOrderedList.Clear;
  NotifyChanged;
end;

function TOrderedCardinalList.Add(Value: Cardinal): Integer;
begin
  if Find(Value,Result) then
    exit
  else
  begin
    FOrderedList.Insert(Result,TObject(Value));
    NotifyChanged;
  end;
end;

procedure TOrderedCardinalList.CopyFrom(Sender: TOrderedCardinalList);
var i : Integer;
begin
  if Self=Sender then
    exit;
  Disable;
  try
    Clear;
    for I := 0 to Sender.Count - 1 do
    begin
      Add(Sender.Get(i));
    end;
  finally
    Enable;
  end;
end;

function TOrderedCardinalList.Count: Integer;
begin
  Result := FOrderedList.Count;
end;

procedure TOrderedCardinalList.Disable;
begin
  inc(FDisabledsCount);
end;

procedure TOrderedCardinalList.Enable;
begin
  if FDisabledsCount<=0 then
    raise Exception.Create('Dev error. Invalid disabled counter');
  dec(FDisabledsCount);
  if (FDisabledsCount=0) and (FModifiedWhileDisabled) then
    NotifyChanged;
end;

function TOrderedCardinalList.Find(const Value: Cardinal; var Index: Integer): Boolean;
var
  L, H, I: Integer;
  C : Int64;
begin
  Result := False;
  L := 0;
  H := FOrderedList.Count - 1;
  while L <= H do
  begin
    I := (L + H) shr 1;
    C := Int64(FOrderedList[I]) - Int64(Value);
    if C < 0 then
      L := I + 1
    else
    begin
      H := I - 1;
      if C = 0 then
      begin
        Result := True;
        L := I;
      end;
    end;
  end;
  Index := L;
end;

function TOrderedCardinalList.Get(index: Integer): Cardinal;
begin
  Result := Cardinal(FOrderedList[index]);
end;

procedure TOrderedCardinalList.NotifyChanged;
begin
  if FDisabledsCount>0 then
  begin
    FModifiedWhileDisabled := True;
    exit;
  end;
  FModifiedWhileDisabled := False;
  if Assigned(FOnListChanged) then
    FOnListChanged(Self);
end;

procedure TOrderedCardinalList.Remove(Value: Cardinal);
var i : Integer;
begin
  if Find(Value,i) then
  begin
    FOrderedList.Delete(i);
    NotifyChanged;
  end;
end;

end.

