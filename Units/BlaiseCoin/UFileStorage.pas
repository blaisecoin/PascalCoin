{
  Copyright (c) 2016 by Albert Molina
  Copyright (c) 2017 by BlaiseCoin developers

  Distributed under the MIT software license, see the accompanying file LICENSE
  or visit http://www.opensource.org/licenses/mit-license.php.

  This unit is a part of BlaiseCoin, a P2P crypto-currency.
}

unit UFileStorage;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface

uses
  Classes, UBlockChain, SyncObjs, UThread;
{$I config.inc}

Type
  TBlockHeader = record
    BlockNumber : Cardinal;
    StreamBlockRelStartPos : Int64;
    BlockSize : Cardinal;
  end; // 16 bytes

  TArrayOfInt64 = array of Int64;

  { TFileStorage }

  TFileStorage = class(TStorage)
  private
    FStorageLock : TPCCriticalSection;
    FBlockChainStream : TFileStream;
    FStreamFirstBlockNumber : Int64;
    FStreamLastBlockNumber : Int64;
    FBlockHeadersFirstBytePosition : TArrayOfInt64;
    FDatabaseFolder: AnsiString;
    FBlockChainFileName : AnsiString;
    function StreamReadBlockHeader(Stream: TStream; StreamBlockHeaderStartPos : Int64; BlockHeaderFirstBlock, Block: Cardinal; var BlockHeader : TBlockHeader): Boolean;
    function StreamBlockRead(Stream : TStream; StreamBlockHeaderStartPos : Int64; BlockHeaderFirstBlock, Block : Cardinal; Operations : TPCOperationsComp) : Boolean;
    function StreamBlockSave(Stream : TStream; StreamBlockHeaderStartPos : Int64; BlockHeaderFirstBlock : Cardinal; Operations : TPCOperationsComp) : Boolean;
    function GetFolder(Const AOrphan : TOrphan): AnsiString;
    function GetBlockHeaderFirstBytePosition(Stream : TStream; Block : Cardinal; var StreamBlockHeaderStartPos : Int64; var BlockHeaderFirstBlock : Cardinal) : Boolean;
    function GetBlockHeaderFixedSize : Int64;
    procedure SetDatabaseFolder(const Value: AnsiString);
    procedure ClearStream;
  protected
    procedure SetReadOnly(const Value: Boolean); override;
    procedure SetOrphan(const Value: TOrphan); override;
    function DoLoadBlockChain(Operations : TPCOperationsComp; Block : Cardinal) : Boolean; override;
    function DoSaveBlockChain(Operations : TPCOperationsComp) : Boolean; override;
    function DoMoveBlockChain(Start_Block : Cardinal; Const DestOrphan : TOrphan; DestStorage : TStorage) : Boolean; override;
    function DoSaveBank : Boolean; override;
    function DoRestoreBank(max_block : Int64) : Boolean; override;
    procedure DoDeleteBlockChainBlocks(StartingDeleteBlock : Cardinal); override;
    function BlockExists(Block : Cardinal) : Boolean; override;
    function LockBlockChainStream : TFileStream;
    procedure UnlockBlockChainStream;
    function LoadBankFileInfo(Const Filename : AnsiString; var BlocksCount : Cardinal) : Boolean;
    function GetFirstBlockNumber: Int64; override;
    function GetLastBlockNumber: Int64; override;
    function DoInitialize : Boolean; override;
  public
    constructor Create(AOwner : TComponent); Override;
    destructor Destroy; Override;
    class function GetBankFileName(Const BaseDataFolder : AnsiString; block : Cardinal) : AnsiString;
    property DatabaseFolder : AnsiString read FDatabaseFolder write SetDatabaseFolder;
    procedure CopyConfiguration(Const CopyFrom : TStorage); override;
    procedure SetBlockChainFile(BlockChainFileName : AnsiString);
  end;

implementation

uses ULog, SysUtils, UConst;

{ TFileStorage }

const
  CT_TBlockHeader_NUL : TBlockHeader = (BlockNumber:0;StreamBlockRelStartPos:0;BlockSize:0);

  CT_GroupBlockSize = 1000;
  CT_SizeOfBlockHeader = 16;
  {
  BlockChain file storage:

  BlockHeader 0 -> From Block 0 to (CT_GroupBlockSize-1)
    Foreach Block:
      BlockNumber : 4 bytes
      StreamBlockRelStartPos : 8 bytes  -> Start pos relative to End of BlockHeader
      BlockSizeH : 4 bytes
      -- Total size of BlockHeader: (4+8+4) * (CT_GroupBlockSize) = 16 * CT_GroupBlockSize
    -- Note: if BlockHeader starts at pos X, it ends at pos X + (16*CT_GroupBlockSize)
  Block 0
    BlockSizeC: 4 bytes
    Data: BlockSizeC bytes
  Block 1
    ...
  Block CT_GroupBlockSize-1

  BlockHeader 1 -> From Block CT_GroupBlockSize to ((CT_GroupBlockSize*2)-1)
    (Same as BlockHeader 1)
  Block CT_GroupBlockSize
    ...
  Block ((CT_GroupBlockSize*2)-1)

  ...
  BlockHeader X -> From (CT_GroupBlockSize*X) to ((CT_GroupBlockSize*(X+1))-1)
  ...

  }

function TFileStorage.BlockExists(Block: Cardinal): Boolean;
var
  StreamBlockHeaderStartPos : Int64; BlockHeaderFirstBlock : Cardinal;
  stream : TStream;
  BlockHeader : TBlockHeader;
begin
  Result := false;
  stream := LockBlockChainStream;
  try
    if not GetBlockHeaderFirstBytePosition(stream,Block,StreamBlockHeaderStartPos,BlockHeaderFirstBlock) then
      exit;
    if not StreamReadBlockHeader(stream,StreamBlockHeaderStartPos,BlockHeaderFirstBlock,Block,BlockHeader) then
      exit;
    Result := (BlockHeader.BlockNumber = Block) and
        (((BlockHeader.BlockNumber mod CT_GroupBlockSize)=0) or (BlockHeader.StreamBlockRelStartPos>0)) and
        (BlockHeader.BlockSize>0);
  finally
    UnlockBlockChainStream;
  end;
end;

procedure TFileStorage.ClearStream;
begin
  FreeAndNil(FBlockChainStream);
  FStreamFirstBlockNumber := 0;
  FStreamLastBlockNumber := -1;
  SetLength(FBlockHeadersFirstBytePosition,0);
end;

procedure TFileStorage.CopyConfiguration(const CopyFrom: TStorage);
begin
  inherited;
  if CopyFrom is TFileStorage then
  begin
    DatabaseFolder := TFileStorage(CopyFrom).DatabaseFolder;
  end;
end;

constructor TFileStorage.Create(AOwner: TComponent);
begin
  inherited;
  FDatabaseFolder := '';
  FBlockChainFileName := '';
  FBlockChainStream := nil;
  SetLength(FBlockHeadersFirstBytePosition,0);
  FStreamFirstBlockNumber := 0;
  FStreamLastBlockNumber := -1;
  FStorageLock := TPCCriticalSection.Create('TFileStorage_StorageLock');
end;

destructor TFileStorage.Destroy;
begin
  inherited;
  ClearStream;
  FreeAndNil(FStorageLock);
end;

procedure TFileStorage.DoDeleteBlockChainBlocks(StartingDeleteBlock: Cardinal);
var
  stream : TStream;
  StreamBlockHeaderStartPos : Int64; BlockHeaderFirstBlock : Cardinal;
  _Header : TBlockHeader;
  _intBlockIndex : Cardinal;
  p : Int64;

  procedure GrowUntilPos(newPos : Int64; DeleteDataStartingAtCurrentPos : Boolean);
  var b : Byte;
  begin
    b := 0;
    if not DeleteDataStartingAtCurrentPos then
    begin
      Stream.Position := Stream.Size;
    end;
    while (Stream.Position<newPos) do
    begin
      Stream.Write(b,1);
    end;
    Stream.Position := newPos;
  end;

begin
  stream := LockBlockChainStream;
  try
    if not GetBlockHeaderFirstBytePosition(stream,StartingDeleteBlock,StreamBlockHeaderStartPos,BlockHeaderFirstBlock) then
      exit;
    if not StreamReadBlockHeader(Stream,StreamBlockHeaderStartPos,BlockHeaderFirstBlock,StartingDeleteBlock,_Header) then
      exit;
    _intBlockIndex := (_Header.BlockNumber-BlockHeaderFirstBlock);
    p := Int64(_intBlockIndex) * Int64(CT_SizeOfBlockHeader);
    // Write null data until end of header
    GrowUntilPos(StreamBlockHeaderStartPos + GetBlockHeaderFixedSize,true);
    // End Stream at _Header
    Stream.Size := Stream.Position + _Header.StreamBlockRelStartPos-1;
  finally
    UnlockBlockChainStream;
  end;
end;

function TFileStorage.DoInitialize: Boolean;
var stream : TStream;
begin
  stream := LockBlockChainStream;
  try
    Result := true;
  finally
    UnlockBlockChainStream;
  end;
end;

function TFileStorage.DoLoadBlockChain(Operations: TPCOperationsComp; Block: Cardinal): Boolean;
var
  stream : TStream;
  StreamBlockHeaderStartPos : Int64; BlockHeaderFirstBlock : Cardinal;
begin
  Result := False;
  stream := LockBlockChainStream;
  try
    if not GetBlockHeaderFirstBytePosition(stream,Block,StreamBlockHeaderStartPos,BlockHeaderFirstBlock) then
      exit;
    Result := StreamBlockRead(stream,StreamBlockHeaderStartPos,BlockHeaderFirstBlock,Block,Operations);
  finally
    UnlockBlockChainStream;
  end;
end;

function TFileStorage.DoMoveBlockChain(Start_Block: Cardinal; const DestOrphan: TOrphan; DestStorage : TStorage): Boolean;
var
  db : TFileStorage;
  ops : TPCOperationsComp;
  b : Cardinal;
begin
  try
    if (Assigned(DestStorage)) and (DestStorage is TFileStorage) then
      db := TFileStorage(DestStorage)
    else
      db := nil;
    try
      if not assigned(db) then
      begin
        db := TFileStorage.Create(nil);
        db.DatabaseFolder := Self.DatabaseFolder;
        db.Bank := Self.Bank;
        db.Orphan := DestOrphan;
        db.FStreamFirstBlockNumber := Start_Block;
      end;
      if db is TFileStorage then
        TFileStorage(db).LockBlockChainStream;
      try
        ops := TPCOperationsComp.Create(Nil);
        try
          b := Start_Block;
          while LoadBlockChainBlock(ops,b) do
          begin
            inc(b);
            db.SaveBlockChainBlock(ops);
          end;
          TLog.NewLog(ltdebug,Classname,'Moved blockchain from "'+Orphan+'" to "'+DestOrphan+'" from block '+inttostr(Start_Block)+' to '+inttostr(b-1));
        finally
          ops.Free;
        end;
      finally
        if db is TFileStorage then
          TFileStorage(db).UnlockBlockChainStream;
      end;
    finally
      if not Assigned(DestStorage) then
        db.Free;
    end;
  except
    on E:Exception do
    begin
      TLog.NewLog(lterror,ClassName,'Error at DoMoveBlockChain: ('+E.ClassName+') '+E.Message);
      raise;
    end;
  end;
end;

function TFileStorage.DoRestoreBank(max_block: Int64): Boolean;
var
  sr: TSearchRec;
  FileAttrs: Integer;
  folder : AnsiString;
  filename,auxfn : AnsiString;
  fs : TFileStream;
  ms : TMemoryStream;
  errors : AnsiString;
  blockscount, c : Cardinal;
begin
  LockBlockChainStream;
  try
    FileAttrs := faArchive;
    folder := GetFolder(Orphan);
    filename := '';
    blockscount := 0;
    if SysUtils.FindFirst(folder+PathDelim+'*.bank', FileAttrs, sr) = 0 then
    begin
      repeat
        if (sr.Attr and FileAttrs) = FileAttrs then
        begin
          auxfn := folder+PathDelim+sr.Name;
          if LoadBankFileInfo(auxfn,c) then
          begin
            if ((c<=max_block) and (c>blockscount)) then
            begin
              filename := auxfn;
              blockscount := c;
            end;
          end;
        end;
      until FindNext(sr) <> 0;
      FindClose(sr);
    end;
    if (filename<>'') then
    begin
      TLog.NewLog(ltinfo,Self.ClassName,'Loading SafeBox with '+inttostr(blockscount)+' blocks from file '+filename);
      fs := TFileStream.Create(filename,fmOpenRead);
      try
        ms := TMemoryStream.Create;
        try
          ms.CopyFrom(fs,0);
          fs.Position := 0;
          ms.Position := 0;
          if not Bank.LoadBankFromStream(ms,errors) then
          begin
            TLog.NewLog(lterror,ClassName,'Error reading bank from file: '+filename+ ' Error: '+errors);
          end;
        finally
          ms.Free;
        end;
      finally
        fs.Free;
      end;
    end;
  finally
    UnlockBlockChainStream;
  end;
end;

function TFileStorage.DoSaveBank: Boolean;
var
  fs: TFileStream;
  bankfilename: AnsiString;
  ms : TMemoryStream;
begin
  Result := true;
  bankfilename := GetBankFileName(GetFolder(Orphan),Bank.BlocksCount);
  if (bankfilename<>'') then
  begin
    fs := TFileStream.Create(bankfilename,fmCreate);
    try
      fs.Size := 0;
      ms := TMemoryStream.Create;
      try
        Bank.SaveBankToStream(ms);
        ms.Position := 0;
        fs.Position := 0;
        fs.CopyFrom(ms,0);
      finally
        ms.Free;
      end;
    finally
      fs.Free;
    end;
  end;
end;

function TFileStorage.DoSaveBlockChain(Operations: TPCOperationsComp): Boolean;
var
  stream : TStream;
  StreamBlockHeaderStartPos : Int64; BlockHeaderFirstBlock : Cardinal;
begin
  Result := False;
  stream := LockBlockChainStream;
  try
    if (Length(FBlockHeadersFirstBytePosition)=0) then
    begin
      // Is saving first block on the stream?
      if (Stream.Size=0) then
      begin
        // Yes! Positioning
        FStreamFirstBlockNumber := Operations.OperationBlock.block;
      end;
      TLog.NewLog(ltdebug,Classname,Format('Saving Block %d on a newer stream, stream first position=%d',[Operations.OperationBlock.block,FStreamFirstBlockNumber]));
    end;
    if not GetBlockHeaderFirstBytePosition(stream,Operations.OperationBlock.block,StreamBlockHeaderStartPos,BlockHeaderFirstBlock) then
      exit;
    Result := StreamBlockSave(stream,StreamBlockHeaderStartPos,BlockHeaderFirstBlock,Operations);
  finally
    UnlockBlockChainStream;
  end;
  if Assigned(Bank) then
    SaveBank;
end;

class function TFileStorage.GetBankFileName(const BaseDataFolder: AnsiString;
  block: Cardinal): AnsiString;
begin
  Result := '';
  if not ForceDirectories(BaseDataFolder) then
    exit;
  // We will store last 5 banks
  Result := BaseDataFolder + PathDelim+'bank'+ inttostr((block div CT_BankToDiskEveryNBlocks) mod 5)+'.bank';
end;

function TFileStorage.GetBlockHeaderFirstBytePosition(Stream : TStream; Block: Cardinal; var StreamBlockHeaderStartPos: Int64; var BlockHeaderFirstBlock: Cardinal): Boolean;
var
  iPos,start : Cardinal;
  bh : TBlockHeader;
begin
  Result := false;
  if Block<FStreamFirstBlockNumber then
  begin
    TLog.NewLog(lterror,Classname,Format('Block %d is lower than Stream First block %d',[Block,FStreamFirstBlockNumber]));
    exit;
  end;
  iPos := (Block-FStreamFirstBlockNumber) div CT_GroupBlockSize;
  if iPos>High(FBlockHeadersFirstBytePosition) then
  begin
    if Length(FBlockHeadersFirstBytePosition)>0 then
    begin
      start := High(FBlockHeadersFirstBytePosition);
    end
    else
    begin
      // Initialize and start at 0
      SetLength(FBlockHeadersFirstBytePosition,1);
      FBlockHeadersFirstBytePosition[0] := 0;
      start := 0;
    end;
    while (start<iPos) do
    begin
      // Read last start position
      if (Stream.Size<(FBlockHeadersFirstBytePosition[start] + GetBlockHeaderFixedSize)) then
      begin
        // This position not exists... This is a Fatal error due must find previos block!
        TLog.NewLog(ltError,Classname,Format('Stream size %d is lower than BlockHeader[%d] position %d + BlockHeaderSize %d',
          [Stream.size,start,FBlockHeadersFirstBytePosition[start],GetBlockHeaderFixedSize]));
        exit;
      end;
      Stream.Position := FBlockHeadersFirstBytePosition[start] + GetBlockHeaderFixedSize - CT_SizeOfBlockHeader;
      // Read last Header
      Stream.Read(bh.BlockNumber,SizeOf(bh.BlockNumber));
      Stream.Read(bh.StreamBlockRelStartPos,SizeOf(bh.StreamBlockRelStartPos));
      Stream.Read(bh.BlockSize,sizeof(bh.BlockSize));
      SetLength(FBlockHeadersFirstBytePosition,length(FBlockHeadersFirstBytePosition)+1);
      FBlockHeadersFirstBytePosition[High(FBlockHeadersFirstBytePosition)] := Stream.Position + bh.StreamBlockRelStartPos + bh.BlockSize;
      inc(start);
    end;
  end;
  StreamBlockHeaderStartPos := FBlockHeadersFirstBytePosition[iPos];
  BlockHeaderFirstBlock := FStreamFirstBlockNumber + (iPos * CT_GroupBlockSize);
  Result := true;
end;

function TFileStorage.GetBlockHeaderFixedSize: Int64;
begin
  Result := (CT_GroupBlockSize* CT_SizeOfBlockHeader);
end;

function TFileStorage.GetFirstBlockNumber: Int64;
begin
  Result := FStreamFirstBlockNumber;
end;

function TFileStorage.GetFolder(const AOrphan: TOrphan): AnsiString;
begin
  if FDatabaseFolder = '' then
    raise Exception.Create('No Database Folder');
  if AOrphan<>'' then
    Result := FDatabaseFolder + PathDelim+AOrphan
  else
    Result := FDatabaseFolder;
  if not ForceDirectories(Result) then
    raise Exception.Create('Cannot create database folder: '+Result);
end;

function TFileStorage.GetLastBlockNumber: Int64;
begin
  Result := FStreamLastBlockNumber;
end;

function TFileStorage.LoadBankFileInfo(const Filename: AnsiString; var BlocksCount: Cardinal): Boolean;
var fs: TFileStream;
begin
  Result := false;
  BlocksCount:=0;
  if not FileExists(Filename) then
    exit;
  fs := TFileStream.Create(Filename,fmOpenRead);
  try
    fs.Position:=0;
    Result := Bank.LoadBankStreamHeader(fs,BlocksCount);
  finally
    fs.Free;
  end;
end;

function TFileStorage.LockBlockChainStream: TFileStream;

  function InitStreamInfo(Stream : TStream; var errors : String) : Boolean;
  var
    mem : TStream;
    iPos : Int64;
    i : Integer;
    bh,lastbh : TBlockHeader;
  begin
    errors := '';
    FStreamFirstBlockNumber := 0;
    FStreamLastBlockNumber := -1;
    SetLength(FBlockHeadersFirstBytePosition,0);
    //
    if stream.Size<GetBlockHeaderFixedSize then
    begin
      if (stream.Size=0) then
      begin
        Result := true;
        exit;
      end
      else
      begin
        // Invalid stream!
        Result := false;
        errors := Format('Invalid stream size %d. Lower than minimum %d',[stream.Size, GetBlockHeaderFixedSize]);
        exit;
      end;
    end;
    // Initialize it
    if stream.Size>GetBlockHeaderFixedSize then
    begin
      SetLength(FBlockHeadersFirstBytePosition,1);
      FBlockHeadersFirstBytePosition[0] := 0;
    end;
    mem := TMemoryStream.Create;
    try
      iPos := 0;
      while (iPos + GetBlockHeaderFixedSize < Stream.Size) do
      begin
        Stream.Position := iPos;
        mem.Size := 0;
        mem.CopyFrom(Stream,GetBlockHeaderFixedSize);
        // Analize it:
        mem.Position := 0;
        for i := 0 to CT_GroupBlockSize-1 do
        begin
          mem.Read(bh.BlockNumber,SizeOf(bh.BlockNumber));
          mem.Read(bh.StreamBlockRelStartPos,SizeOf(bh.StreamBlockRelStartPos));
          mem.Read(bh.BlockSize,sizeof(bh.BlockSize));
          if (i=0) and (iPos=0) then
          begin
            FStreamFirstBlockNumber := bh.BlockNumber;
            FStreamLastBlockNumber := bh.BlockNumber;
            if (0<>bh.StreamBlockRelStartPos) then
            begin
              errors := Format('Invalid first block start rel pos %d',[bh.StreamBlockRelStartPos]);
              result := false;
              exit;
            end;
          end
          else
          begin
            if (bh.BlockNumber=0) then
            begin
              // End here
              break;
            end;
            if (lastbh.BlockNumber+1<>bh.BlockNumber) or
              ((lastbh.StreamBlockRelStartPos+lastbh.BlockSize<>bh.StreamBlockRelStartPos) and (i>0)) Or
              ((0<>bh.StreamBlockRelStartPos) and (i=0)) then
            begin
              errors := Format('Invalid check on block header. iPos=%d i=%d Number=%d relstart=%d size=%d',[iPos,i,bh.BlockNumber,bh.StreamBlockRelStartPos,bh.BlockSize]);
              result := false;
              exit;
            end
            else
            begin
              FStreamLastBlockNumber := bh.BlockNumber;
            end;
          end;
          lastbh := bh;
        end;
        iPos := iPos + GetBlockHeaderFixedSize + lastbh.StreamBlockRelStartPos + lastBh.BlockSize;
      end;
      Result := true;
    finally
      mem.Free;
    end;
  end;

var
  fn : TFileName;
  fm : Word;
  exists : Boolean;
  errors : String;
begin
  TPCThread.ProtectEnterCriticalSection(Self,FStorageLock);
  try
    if not Assigned(FBlockChainStream) then
    begin
      if FBlockChainFileName<>'' then
      begin
        fn := FBlockChainFileName
      end else
      begin
        fn := GetFolder(Orphan)+PathDelim+'BlockChainStream.blocks';
      end;
      exists := FileExists(fn);
      if ReadOnly then
      begin
        if exists then
          fm := fmOpenRead+fmShareDenyNone
        else
          raise Exception.Create('FileStorage not exists for open ReadOnly: '+fn);
      end
      else
      begin
        if exists then
          fm := fmOpenReadWrite+fmShareDenyWrite
        else
          fm := fmCreate+fmShareDenyWrite
      end;
      FBlockChainStream := TFileStream.Create(fn,fm);
      // Init stream
      if not InitStreamInfo(FBlockChainStream,errors) then
      begin
        TLog.NewLog(lterror,ClassName,errors);
        raise Exception.Create('Error reading File: '+errors);
      end;
    end;
  except
    FStorageLock.Release;
    raise;
  end;
  Result := FBlockChainStream;
end;

procedure TFileStorage.SetBlockChainFile(BlockChainFileName: AnsiString);
begin
  ClearStream;
  FBlockChainFileName := BlockChainFileName;
end;

procedure TFileStorage.SetDatabaseFolder(const Value: AnsiString);
begin
  if FDatabaseFolder=Value then
    exit;
  FDatabaseFolder := Value;
  ClearStream;
end;

procedure TFileStorage.SetOrphan(const Value: TOrphan);
begin
  inherited;
  ClearStream;
end;

procedure TFileStorage.SetReadOnly(const Value: Boolean);
begin
  inherited;
  ClearStream;
end;

function TFileStorage.StreamBlockRead(Stream : TStream; StreamBlockHeaderStartPos : Int64; BlockHeaderFirstBlock, Block : Cardinal; Operations : TPCOperationsComp) : Boolean;
var
  p : Int64;
  errors : AnsiString;
  _BlockSizeC : Cardinal;
  _Header : TBlockHeader;
  _ops : TStream;
begin
  Result := StreamReadBlockHeader(Stream,StreamBlockHeaderStartPos,BlockHeaderFirstBlock,Block,_Header);
  if not Result then
    exit;
  // Calculating block position
  p := (StreamBlockHeaderStartPos + GetBlockHeaderFixedSize) +
     (_Header.StreamBlockRelStartPos);
  if Stream.Size<(p + _Header.BlockSize) then
  begin
    TLog.NewLog(ltError,Classname,Format(
      'Invalid stream size. Block %d need to be at relative %d after %d = %d BlockSize:%d (Size %d)',
      [Block,_Header.StreamBlockRelStartPos,(StreamBlockHeaderStartPos + GetBlockHeaderFixedSize),p,_Header.BlockSize,Stream.Size]));
    exit;
  end;
  Stream.Position := p;
  // Read the block
  // Reading size
  Stream.Read(_BlockSizeC,sizeof(_BlockSizeC));
  if (_BlockSizeC>(_Header.BlockSize+sizeof(_BlockSizeC))) then
  begin
    TLog.NewLog(lterror,Classname,Format('Corruption at stream Block size. Block %d SizeH:%d SizeC:%d',[Block,
      _Header.BlockSize,_BlockSizeC]));
    exit;
  end;
  // Reading Block
  _ops := TMemoryStream.Create;
  try
    _ops.CopyFrom(Stream,_BlockSizeC);
    _ops.Position := 0;
    if not Operations.LoadBlockFromStorage(_ops,errors) then
    begin
      TLog.NewLog(lterror,Classname,'Error reading OperationBlock '+inttostr(Block)+' from stream. Errors: '+errors);
      exit;
    end;
    Result := true;
  finally
    _ops.Free;
  end;
end;

function TFileStorage.StreamBlockSave(Stream : TStream; StreamBlockHeaderStartPos : Int64; BlockHeaderFirstBlock : Cardinal; Operations : TPCOperationsComp) : Boolean;
  procedure GrowUntilPos(newPos : Int64; DeleteDataStartingAtCurrentPos : Boolean);
  var null_buff : Array[1..CT_GroupBlockSize] of Byte;
    i : Int64;
  begin
    if not DeleteDataStartingAtCurrentPos then
    begin
      Stream.Position := Stream.Size;
    end;
    if (stream.Position<newPos) then
    begin
      FillChar(null_buff,length(null_buff),0);
      while (Stream.Position<newPos) do
      begin
        i := newPos - Stream.Position;
        if i>length(null_buff) then
          i := length(null_buff);
        Stream.WriteBuffer(null_buff,i);
      end;
    end;
    Stream.Position := newPos;
  end;

var
  p : Int64;
  c : Cardinal;
  _Header, _HeaderPrevious : TBlockHeader;
  _intBlockIndex : Cardinal;
  _ops : TStream;
begin
  Result := false;
  _Header := CT_TBlockHeader_NUL;
  _Header.BlockNumber := Operations.OperationBlock.block;
  if BlockHeaderFirstBlock>_Header.BlockNumber then
    raise Exception.Create('Dev error 20160917-3')
  else
    if BlockHeaderFirstBlock<_Header.BlockNumber then
    begin
      Result := StreamReadBlockHeader(Stream,StreamBlockHeaderStartPos,BlockHeaderFirstBlock,_Header.BlockNumber-1,_HeaderPrevious);
      if not Result then
      begin
        raise Exception.Create('Cannot found header of previous block '+inttostr(Operations.OperationBlock.block));
      end;
     _Header.StreamBlockRelStartPos := _HeaderPrevious.StreamBlockRelStartPos + _HeaderPrevious.BlockSize;
    end
    else
    begin
      // First block of the stream
      _Header.StreamBlockRelStartPos := 0;
    end;
  _ops := TMemoryStream.Create;
  try
    Operations.SaveBlockToStorage(_ops);
    _Header.BlockSize := _ops.Size;
    // Positioning until Header Position to save Header data
    _intBlockIndex := (_Header.BlockNumber-BlockHeaderFirstBlock);
    p := Int64(_intBlockIndex) * Int64(CT_SizeOfBlockHeader);
    GrowUntilPos(StreamBlockHeaderStartPos + p,false);
    // Save Header
    Stream.Write(_Header.BlockNumber,sizeof(_Header.BlockNumber));
    Stream.Write(_Header.StreamBlockRelStartPos,sizeof(_Header.StreamBlockRelStartPos));
    c := _Header.BlockSize + sizeof(c);
    Stream.Write(c,sizeof(_Header.BlockSize));
    // Positioning until Header end
    GrowUntilPos(StreamBlockHeaderStartPos + GetBlockHeaderFixedSize,true);
    // and now positioning until Data:
    GrowUntilPos(StreamBlockHeaderStartPos + GetBlockHeaderFixedSize + _Header.StreamBlockRelStartPos, false );
    // Save stream size
    Stream.Write(_Header.BlockSize,sizeof(_Header.BlockSize));
    // Save Data
    _ops.Position := 0;
    Stream.CopyFrom(_ops,_ops.Size);
    FStreamLastBlockNumber := Operations.OperationBlock.block;
  finally
    _ops.Free;
  end;
end;

function TFileStorage.StreamReadBlockHeader(Stream: TStream;
  StreamBlockHeaderStartPos: Int64; BlockHeaderFirstBlock, Block: Cardinal;
  var BlockHeader: TBlockHeader): Boolean;
begin
  Result := false;
  BlockHeader := CT_TBlockHeader_NUL;
  if (BlockHeaderFirstBlock>Block) then
    raise Exception.Create('Dev error 20160917-1');
  if (BlockHeaderFirstBlock+CT_GroupBlockSize)<Block then
    raise Exception.Create('Dev error 20160917-2');
  if Stream.Size< (StreamBlockHeaderStartPos + (GetBlockHeaderFixedSize)) then
  begin
    // not log... it's normal when finding block   TLog.NewLog(ltError,Classname,Format('Invalid stream size %d < (%d + %d) Reading block %d',[Stream.Size,StreamBlockHeaderStartPos,GetBlockHeaderFixedSize,Block]));
    exit;
  end;
  Stream.Position := StreamBlockHeaderStartPos + (CT_SizeOfBlockHeader*(Block-BlockHeaderFirstBlock));
  // Reading block header
  if Stream.Read(BlockHeader.BlockNumber,sizeof(BlockHeader.BlockNumber))<sizeof(BlockHeader.BlockNumber) then
    exit;
  if Stream.Read(BlockHeader.StreamBlockRelStartPos,sizeof(BlockHeader.StreamBlockRelStartPos))<sizeof(BlockHeader.StreamBlockRelStartPos) then
    exit;
  if Stream.Read(BlockHeader.BlockSize,sizeof(BlockHeader.BlockSize))<sizeof(BlockHeader.BlockSize) then
    exit;
  Result := (BlockHeader.BlockNumber = Block);
end;

procedure TFileStorage.UnlockBlockChainStream;
begin
  FStorageLock.Release;
end;

end.

