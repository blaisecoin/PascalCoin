unit UGPUMining;

{$mode delphi}

{ Copyright (c) 2017 by Albert Molina

  Distributed under the MIT software license, see the accompanying file LICENSE
  or visit http://www.opensource.org/licenses/mit-license.php.

  This unit is a part of Pascal Coin, a P2P crypto currency without need of
  historical operations.

  if you like it, consider a donation using BitCoin:
  16K3HCZRhFUtM8GdWRcfKeaa6KsuyxZaYk

  }

interface

uses
  Classes, SysUtils, CL_Platform, CL, CL_GL, DelphiCL, dglOpenGL, USha256, UPoolMinerThreads, UPoolMining,
  UThread, UTime, SyncObjs, UCrypto, ULog;

Type

  { TGPUDeviceThread }

  TGPUDeviceThread = class(TCustomMinerDeviceThread)
  private
    FNeedNewDevice : Boolean;
    FDevice: Integer;
    FPlatform: Integer;
    FLock : TCriticalSection;
    FDCLDevice : TDCLDevice;
    FDCLProgram: TDCLProgram;
    FDCLCommandQueue: TDCLCommandQueue;
    FDCLKernel: TDCLKernel;
    FProgramFileName: String;
    FChangeTimestampAndNOnceBytePos : Integer;
    FKernelOutputBuffer : TDCLBuffer;
    FKernelInputBuffer : TDCLBuffer;
    FKernelArg1 : Array[0..28] of TCL_int;
    FKernelArg2 : TCL_int;
    FReadyToGPU : Boolean;
    procedure SetDevice(AValue: Integer);
    procedure SetPlatform(AValue: Integer);
    procedure SetProgramFileName(AValue: String);
  protected
    procedure BCExecute; override;
    procedure SetMinerValuesForWork(const Value: TMinerValuesForWork); override;
    procedure UpdateState; override;
    procedure UpdateBuffers;
  public
    constructor Create(PoolMinerThread : TPoolMinerThread; InitialMinerValuesForWork : TMinerValuesForWork); override;
    destructor Destroy; override;
    property Platform : Integer read FPlatform write SetPlatform;
    property Device : Integer read FDevice write SetDevice;
    property ProgramFileName : String read FProgramFileName write SetProgramFileName;
    function MinerDeviceName : String; override;
    function GetState : String; override;
  end;

  { TGPUDriver }

  TGPUDriver = class
  private
    FHasOpenCL: Boolean;
    FPlatforms: TDCLPlatforms;
    function GetPlatforms: TDCLPlatforms;
  public
    constructor Create;
    destructor Destroy; override;
    class function GPUDriver : TGPUDriver;
    property HasOpenCL : Boolean read FHasOpenCL;
    property Platforms : TDCLPlatforms read GetPlatforms;
  end;



implementation

var _initstatus : Integer;
  _GPUDriver : TGPUDriver;

function bswap(x: Cardinal): Cardinal;
begin
  bswap:=
    ((x and $000000FF) shl 24) +
    ((x and $0000FF00) shl  8) +
    ((x and $00FF0000) shr  8) +
    ((x and $FF000000) shr 24);
end;

{ TGPUDriver }

function TGPUDriver.GetPlatforms: TDCLPlatforms;
begin
  if not Assigned(FPlatforms) then begin
    if not FHasOpenCL then Raise Exception.create('No OpenCL available on this computer!');
    FPlatforms := TDCLPlatforms.Create;
  end;
  Result := FPlatforms;
end;

constructor TGPUDriver.Create;
begin
  FPlatforms := nil;
  FHasOpenCL:=InitOpenCL;
  _GPUDriver := Self;
end;

destructor TGPUDriver.Destroy;
begin
  if _GPUDriver=Self then _GPUDriver := nil;
  FreeAndNil(FPlatforms);
  inherited Destroy;
end;

class function TGPUDriver.GPUDriver: TGPUDriver;
begin
  if not assigned(_GPUDriver) then begin
    _GPUDriver := TGPUDriver.Create;
  end;
  Result := _GPUDriver;
end;

{ TGPUDeviceThread }

procedure TGPUDeviceThread.BCExecute;
Const CT_LAPS_ROUND = 16777216; // 2^24 = 16777216 2^22 = 4194304     2^20 = 1048576
      CT_MAX_LAPS = 256; // 2^8 = 256 2^10 = 1024
var Timestamp, nOnce : Cardinal;
  nLap : Cardinal;
  baseRealTC,baseHashingTC,finalHashingTC,lastNotifyTC : Cardinal;
  AuxStats : TMinerStats;
begin
  UpdateState;
  nLap := 0;
  AuxStats := CT_TMinerStats_NULL;
  lastNotifyTC :=GetTickCount;
  while not Terminated do begin
    if (Paused) then begin
      sleep(1);
    end else begin
      baseRealTC := GetTickCount;
      FLock.Acquire;
      try
      //  AuxStats := CT_TMinerStats_NULL;
        if FReadyToGPU then begin
          Timestamp := UnivDateTimeToUnix(DateTime2UnivDateTime(now));
          if Timestamp<=PoolMinerThread.GlobalMinerValuesForWork.timestamp then Timestamp := PoolMinerThread.GlobalMinerValuesForWork.timestamp+1;
          FKernelArg1[ (FChangeTimestampAndNOnceBytePos div 4) ] := bswap(Timestamp);
          // FKernelArg1[24] = Position to save nOnce
          FKernelArg1[24] := (FChangeTimestampAndNOnceBytePos div 4)+1;
          // FKernelArg1[25] = high-order 10 bits for nOnce (see .cl source file)
          FKernelArg1[25] := nLap;
          //
          FKernelInputBuffer := FDCLDevice.CreateBuffer(29*4, @FKernelArg1[0], [mfReadWrite, mfCopyHostPtr]);
          try
            FDCLKernel.SetArg(0,FKernelInputBuffer);
            FDCLKernel.SetArg(1,FKernelOutputBuffer);
            baseHashingTC := GetTickCount;
            FDCLCommandQueue.Execute(FDCLKernel,CT_LAPS_ROUND);
            finalHashingTC := GetTickCount;
          finally
            FreeAndNil(FKernelInputBuffer);
          end;
          FDCLCommandQueue.ReadBuffer(FKernelOutputBuffer,4,@FKernelArg2);
          if FKernelArg2<>0 then begin
            nOnce := bswap(FKernelArg2);
            FreeAndNil(FKernelOutputBuffer);
            FKernelArg2 := 0; // Save nOnce=0 (not valid)
            FKernelOutputBuffer := FDCLDevice.CreateBuffer(4,@FKernelArg2,[mfReadWrite, mfCopyHostPtr {mfCopyHostPtr mfUseHostPtr}]);
            // FOUND A NONCE !!!
            inc(AuxStats.WinsCount);
            FLock.Release;
            try
              FoundNOnce(Timestamp,nOnce);
            finally
              FLock.Acquire;
            end;
          end;
          if (nLap<CT_MAX_LAPS) then inc(nLap) else nLap := 0;
          inc(AuxStats.RoundsCount,CT_LAPS_ROUND);
        end;
      finally
        FLock.Release;
      end;
      if (AuxStats.RoundsCount>0) then begin
        inc(AuxStats.WorkingMillisecondsTotal,GetTickCount - baseRealTC);
        inc(AuxStats.WorkingMillisecondsHashing,finalHashingTC-baseHashingTC);
      end;
    end;
    if (lastNotifyTC + 200 < GetTickCount) then begin
      sleep(1);
      lastNotifyTC := GetTickCount;
      UpdateDeviceStats(AuxStats);
      AuxStats := CT_TMinerStats_NULL;
    end;
  end;
end;

constructor TGPUDeviceThread.Create(PoolMinerThread: TPoolMinerThread; InitialMinerValuesForWork: TMinerValuesForWork);
begin
  FReadyToGPU := false;
  FDevice:=-1;
  FPlatform:=-1;
  FNeedNewDevice:=false;
  FProgramFileName:='';
  FLock := TCriticalSection.Create;
  FDCLDevice := nil;
  FDCLProgram := nil;
  FDCLCommandQueue := nil;
  FDCLKernel := nil;
  FKernelInputBuffer := nil;
  FKernelOutputBuffer := nil;
  inherited Create(PoolMinerThread, InitialMinerValuesForWork);
end;

destructor TGPUDeviceThread.Destroy;
begin
  FreeAndNil(FLock);
  FreeAndNil(FDCLCommandQueue);
  FreeAndNil(FKernelOutputBuffer);
  FreeAndNil(FKernelInputBuffer);
  FreeAndNil(FDCLKernel);
  FreeAndNil(FDCLProgram);
  inherited Destroy;
end;

function TGPUDeviceThread.GetState: String;
begin
  if Paused then result := 'GPU miner is paused'
  else if (IsMining) and Assigned(FDCLDevice) then Result := 'GPU is mining on p '+IntToStr(Platform)+' d '+IntToStr(Device)+' Compute units:'+IntToStr(FDCLDevice.MaxComputeUnits)+' Freq:'+IntToStr(FDCLDevice.MaxClockFrequency)
  else Result := 'GPU miner is waiting for configuration...';
end;

function TGPUDeviceThread.MinerDeviceName: String;
begin
  Result := 'GPU p'+inttostr(FPlatform)+' d'+IntToStr(FDevice);
  if assigned(FDCLDevice) then begin
    Result := Result+' Name:'+Trim(FDCLDevice.Name)+' CU:'+IntToStr(FDCLDevice.MaxComputeUnits)+' Freq:'+IntToStr(FDCLDevice.MaxClockFrequency);
  end else Result := Result + ' (no info)';
end;

procedure TGPUDeviceThread.SetDevice(AValue: Integer);
begin
  if FDevice=AValue then Exit;
  FDevice:=AValue;
  FNeedNewDevice := true;
  UpdateState;
end;

procedure TGPUDeviceThread.SetMinerValuesForWork(const Value: TMinerValuesForWork);
begin
  inherited;
  UpdateBuffers;
end;

procedure TGPUDeviceThread.SetPlatform(AValue: Integer);
begin
  if FPlatform=AValue then Exit;
  FPlatform:=AValue;
  FNeedNewDevice := true;
  UpdateState;
end;

procedure TGPUDeviceThread.SetProgramFileName(AValue: String);
begin
  if FProgramFileName=AValue then Exit;
  FProgramFileName:=AValue;
  FNeedNewDevice:=true;
  UpdateState;
end;

procedure TGPUDeviceThread.UpdateState;
begin
  FLock.Acquire;
  try
    if FNeedNewDevice then begin
      FDCLDevice := nil;
      FreeAndNil(FDCLCommandQueue);
      FreeAndNil(FKernelInputBuffer);
      FreeAndNil(FKernelOutputBuffer);
      FreeAndNil(FDCLKernel);
      FreeAndNil(FDCLProgram);
      FNeedNewDevice:=false;
      if (FDevice>=0) and (FPlatform>=0) and (Assigned(_GPUDriver)) then begin
        if (_GPUDriver.platforms.PlatformCount>=FPlatform) then begin
          if (_GPUDriver.platforms.Platforms[FPlatform].DeviceCount>=FDevice) then begin
            FDCLDevice := _GPUDriver.Platforms.Platforms[FPlatform].Devices[FDevice]^;
          end;
        end;
      end;
      if Assigned(FDCLDevice) and (FProgramFileName<>'') and (FileExists(FProgramFileName)) then begin
        FDCLCommandQueue := FDCLDevice.CreateCommandQueue;
        FDCLProgram := FDCLDevice.CreateProgram(FProgramFileName);
        FKernelArg2 := 0; // Save nOnce=0 (not valid)
        FKernelOutputBuffer := FDCLDevice.CreateBuffer(4,@FKernelArg2,[mfReadWrite, mfCopyHostPtr {mfCopyHostPtr mfUseHostPtr}]);
        FDCLKernel := FDCLProgram.CreateKernel('pascalcoin');
      end;
    end;
    UpdateBuffers;
  finally
    FLock.Release;
  end;
  inherited;
end;

procedure TGPUDeviceThread.UpdateBuffers;
var stateforlastchunk : TSHA256HASH;
  bufferForLastChunk : TChunk;
  i : Integer;
  canWork : Boolean;
  s,s2 : AnsiString;
  b : Byte;
  c1,c2 : Cardinal;
begin
  FLock.Acquire;
  try
    FReadyToGPU := (MinerValuesForWork.part1<>'') and (Assigned(FDCLKernel));
    if (not FReadyToGPU) then begin
      IsMining := false;
      exit;
    end;
    Repeat
      i := Length(MinerValuesForWork.part1)+Length(MinerValuesForWork.payload_start)+Length(MinerValuesForWork.part3)+8;
      canWork := CanBeModifiedOnLastChunk(i,FChangeTimestampAndNOnceBytePos);
      if not canWork then FMinerValuesForWork.payload_start:=MinerValuesForWork.payload_start+'.';
    until (canWork);
    FillChar(FKernelArg1[0],29*4,#0);
    s := MinerValuesForWork.part1+MinerValuesForWork.payload_start+MinerValuesForWork.part3+'00000000';
    PascalCoinPrepareLastChunk(s,stateforlastchunk,bufferForLastChunk);
    // FKernelArg1[0..15] = data for last chunk
    move(bufferForLastChunk[0],FKernelArg1[0],16*4);
    For i:=0 to 15 do begin
      FKernelArg1[i] := bswap(FKernelArg1[i]);
    end;
    // FKernelArg1[16..23] = previous chunk result
    move(stateforlastchunk[0],FKernelArg1[16],8*4);
    // FKernelArg1[24] = Position to save nOnce
    // FKernelArg1[25] = high-order 12 bits for nOnce (see .cl file to know)
    // FKernelArg1[26..28] = Mask (obtained  from target_pow)
    FillChar(FKernelArg1[26],4*3,#0);
    s := MinerValuesForWork.target_pow;
    i := 1;
    while (length(s)>=i) and (i<=4*3) do begin
      b := Byte(s[i]);
      b := b XOR $FF;
      c1 := FKernelArg1[26+((i-1) div 4)]; // Last value
      c2 := b SHL (((4-i) mod 4)*8);
      c2 := c1 or c2;
      FKernelArg1[26+((i-1) div 4)] := c2;
      if (b<>$FF) then break; // Found first 1 bit
      inc(i);
    end;
    IsMining := true;
  finally
    FLock.Release;
  end;
end;

initialization
  _initstatus := 0;
finalization
  FreeAndNil(_GPUDriver);
end.

