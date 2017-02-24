{
  Copyright (c) 2016 by Albert Molina
  Copyright (c) 2017 by BlaiseCoin developers

  Distributed under the MIT software license, see the accompanying file LICENSE
  or visit http://www.opensource.org/licenses/mit-license.php.

  This unit is a part of BlaiseCoin, a P2P crypto-currency.
}

unit UAppParams;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface

uses
  Classes;

Type
  TAppParamType = (ptString, ptInteger, ptLongWord, ptInt64, ptBoolean, ptStream);

  TAppParams = class;

  TAppParam = class
    FAppParams : TAppParams;
    function LoadFromStream(Stream : TStream) : Boolean;
    procedure SaveToStream(Stream : TStream);
  private
    FParamName: AnsiString;
    FValue: Variant;
    FParamType: TAppParamType;
    procedure SetParamName(const Value: AnsiString);
    procedure SetValue(const Value: Variant);
    procedure SetParamType(const Value: TAppParamType);
    function GetIsNull: Boolean;
  protected
  published
  public
    Constructor Create(AParamName : AnsiString);
    property ParamName : AnsiString read FParamName write SetParamName;
    property Value : Variant read FValue write SetValue;
    property ParamType : TAppParamType read FParamType write SetParamType;
    procedure SetAsInteger(IntValue : Integer);
    procedure SetAsCardinal(CardValue : Cardinal);
    procedure SetAsString(StringValue : AnsiString);
    procedure SetAsInt64(Int64Value : Int64);
    procedure SetAsBoolean(BoolValue : Boolean);
    procedure SetAsStream(Stream : TStream);
    property IsNull : Boolean read GetIsNull;
    function GetAsString(Const DefValue : AnsiString): AnsiString;
    function GetAsBoolean(Const DefValue : Boolean): Boolean;
    function GetAsInteger(Const DefValue : Integer): Integer;
    function GetAsInt64(Const DefValue : Int64): Int64;
    function GetAsStream(Stream : TStream) : Integer;
  end;

  TAppParams = class(TComponent)
  private
    FParamsStream : TFileStream;
    FParams : TList;
    FFileName: AnsiString;
    function LoadFromStream(Stream : TStream) : Boolean;
    procedure SaveToStream(Stream : TStream);
    function GetParam(ParamName: AnsiString): TAppParam;
    procedure InternalClear;
    function IndexOfParam(Const ParamName : AnsiString) : Integer;
    procedure SetFileName(const Value: AnsiString);
    procedure Save;
  protected
  public
    Constructor Create(AOwner : TComponent); override;
    Destructor Destroy; override;
    class function AppParams : TAppParams;
    property FileName : AnsiString read FFileName write SetFileName;
    property ParamByName[ParamName : AnsiString] : TAppParam read GetParam;
    procedure Clear;
    procedure Delete(Const ParamName : AnsiString);
    function Count : Integer;
    function Param(index : Integer) : TAppParam;
    function FindParam(Const ParamName : AnsiString) : TAppParam;
  end;

implementation

uses
  Variants, UAccounts, SysUtils;

Const
  CT_AppParams_File_Magic = 'TAppParams';

var _appParams : TAppParams;

{ TAppParam }

constructor TAppParam.Create(AParamName: AnsiString);
begin
  FAppParams := nil;
  FParamName := AParamName;
  FValue := Null;
end;

function TAppParam.GetAsBoolean(const DefValue: Boolean): Boolean;
begin
  if IsNull then Result := DefValue
  else begin
    try
      Result := FValue;
    except
      Result := DefValue;
    end;
  end;
end;

function TAppParam.GetAsInt64(const DefValue: Int64): Int64;
begin
  if IsNull then Result := DefValue
  else begin
    try
      Result := FValue;
    except
      Result := DefValue;
    end;
  end;
end;

function TAppParam.GetAsInteger(const DefValue: Integer): Integer;
begin
  if IsNull then Result := DefValue
  else begin
    try
      Result := FValue;
    except
      Result := DefValue;
    end;
  end;
end;

function TAppParam.GetAsStream(Stream: TStream): Integer;
var s : AnsiString;
begin
  Stream.Size := 0;
  if IsNull then Result := 0
  else begin
    s := VarToStrDef(FValue,'');
    Stream.Size := 0;
    Stream.WriteBuffer(s[1],length(s));
    Stream.Position := 0;
  end;
end;

function TAppParam.GetAsString(Const DefValue : AnsiString): AnsiString;
begin
  if IsNull then Result := DefValue
  else Result := VarToStrDef(FValue,DefValue);
end;

function TAppParam.GetIsNull: Boolean;
begin
  Result := VarIsNull( FValue );
end;

function TAppParam.LoadFromStream(Stream: TStream)  : Boolean;
var bpt : Byte;
  pt : TAppParamType;
  s : AnsiString;
  i : Integer;
  c : Cardinal;
  i64 : Int64;
begin
  Result := false;
  if TStreamOp.ReadAnsiString(Stream,FParamName)<0 then exit;
  Stream.Read(bpt,1);
  if (bpt>=Integer(low(pt))) And (bpt<=Integer(high(pt))) then pt := TAppParamType(bpt)
  else pt := ptString;
  FParamType := pt;
  Stream.Read(bpt,1);
  if bpt=0 then FValue := Null
  else begin
    case pt of
      ptString : begin
        if TStreamOp.ReadAnsiString(Stream,s)<0 then exit;
        FValue := s;
      end;
      ptInteger : begin
        if Stream.Read(i,sizeof(i))<sizeof(i) then exit;
        FValue := i;
      end;
      ptLongWord : begin
        if Stream.Read(c,sizeof(c))<sizeof(c) then exit;
        FValue := c;
      end;
      ptInt64 : begin
        if Stream.Read(i64,sizeof(i64))<sizeof(i64) then exit;
        FValue := i64;
      end;
      ptBoolean : begin
        if Stream.Read(bpt,sizeof(bpt))<sizeof(bpt) then exit;
        if bpt=0 then FValue := false
        else FValue := true;
      end;
      ptStream : begin
        if TStreamOp.ReadAnsiString(Stream,s)<0 then exit;
        FValue := s;
      End
    else
      raise Exception.Create('Development error 20160613-1');
    end;
  end;
  Result := true;
end;

procedure TAppParam.SaveToStream(Stream: TStream);
var b : Byte;
  i : Integer;
  c : Cardinal;
  i64 : Int64;
begin
  TStreamOp.WriteAnsiString(Stream,FParamName);
  b := Byte(FParamType);
  Stream.Write(b,1);
  if IsNull then begin
    b := 0;
    Stream.Write(b,1);
  end else begin
    b := 1;
    Stream.Write(b,1);
    case FParamType of
      ptString : begin
        TStreamOp.WriteAnsiString(Stream,VarToStr(FValue));
      end;
      ptInteger : begin
        i := FValue;
        Stream.Write(i,sizeof(i));
      end;
      ptLongWord : begin
        c := FValue;
        Stream.Write(c,sizeof(c));
      end;
      ptInt64 : begin
        i64 := FValue;
        Stream.Write(i64,sizeof(i64));
      end;
      ptBoolean : begin
        if FValue then b := 1
        else b := 0;
        Stream.Write(b,sizeof(b));
      end;
      ptStream : begin
        TStreamOp.WriteAnsiString(Stream,VarToStrDef(FValue,''));
      End
    else
      raise Exception.Create('Development error 20160613-2');
    end;
  end;
end;

procedure TAppParam.SetAsBoolean(BoolValue: Boolean);
begin
  FParamType := ptBoolean;
  FValue := BoolValue;
  if Assigned(FAppParams) then FAppParams.Save;
end;

procedure TAppParam.SetAsCardinal(CardValue: Cardinal);
begin
  FParamType := ptLongWord;
  FValue := CardValue;
  if Assigned(FAppParams) then FAppParams.Save;
end;

procedure TAppParam.SetAsInt64(Int64Value: Int64);
begin
  FParamType := ptInt64;
  FValue := Int64Value;
  if Assigned(FAppParams) then FAppParams.Save;
end;

procedure TAppParam.SetAsInteger(IntValue: Integer);
begin
  FParamType := ptInteger;
  FValue := IntValue;
  if Assigned(FAppParams) then FAppParams.Save;
end;

procedure TAppParam.SetAsStream(Stream: TStream);
var s : AnsiString;
begin
  Stream.Position := 0;
  setlength(s,Stream.Size);
  Stream.ReadBuffer(s[1],Stream.Size);
  FParamType := ptString;
  FValue := s;
  if Assigned(FAppParams) then FAppParams.Save;
end;

procedure TAppParam.SetAsString(StringValue: AnsiString);
begin
  if (FParamType=ptString) And (GetAsString('')=StringValue) then exit;

  FParamType := ptString;
  FValue := StringValue;
  if Assigned(FAppParams) then FAppParams.Save;
end;

procedure TAppParam.SetParamName(const Value: AnsiString);
begin
  FParamName := Value;
  if Assigned(FAppParams) then FAppParams.Save;
end;

procedure TAppParam.SetParamType(const Value: TAppParamType);
begin
  FParamType := Value;
  if Assigned(FAppParams) then FAppParams.Save;
end;

procedure TAppParam.SetValue(const Value: Variant);
begin
  FValue := Value;
  if Assigned(FAppParams) then FAppParams.Save;
end;

{ TAppParams }

class function TAppParams.AppParams: TAppParams;
begin
  if not Assigned(_appParams) then begin
    _appParams := TAppParams.Create(nil);
  end;
  Result := _appParams;
end;

procedure TAppParams.Clear;
begin
  InternalClear;
  Save;
end;

function TAppParams.Count: Integer;
begin
  Result := FParams.Count;
end;

constructor TAppParams.Create(AOwner: TComponent);
begin
  inherited;
  FParams := TList.Create;
  FFileName := '';
  FParamsStream := nil;
  if _appParams=nil then _appParams := Self;

end;

procedure TAppParams.Delete(const ParamName: AnsiString);
var P : TAppParam;
  i : Integer;
begin
  i := IndexOfParam(ParamName);
  if i<0 then exit;
  P := FParams[i];
  FParams.Delete(i);
  P.Free;
  Save;
end;

destructor TAppParams.Destroy;
begin
  FreeAndnil(FParamsStream);
  InternalClear;
  FParams.Free;
  inherited;
  if _appParams=Self then _appParams := nil;

end;

function TAppParams.FindParam(const ParamName: AnsiString): TAppParam;
var i : Integer;
begin
  i := IndexOfParam(ParamName);
  if i>=0 then Result := FParams[i]
  else Result := nil;
end;

function TAppParams.GetParam(ParamName: AnsiString): TAppParam;
var i : Integer;
  P : TAppParam;
begin
  i := IndexOfParam(ParamName);
  if i<0 then begin
    P := TAppParam.Create(ParamName);
    P.FAppParams := Self;
    FParams.Add(P);
  end else P := FParams[i];
  Result := P;
end;

function TAppParams.IndexOfParam(const ParamName: AnsiString): Integer;
begin
  for Result := 0 to FParams.Count - 1 do begin
    if AnsiSameText(ParamName,TAppParam(FParams[Result]).ParamName) then exit;
  end;
  Result := -1;
end;

procedure TAppParams.InternalClear;
var P : TAppParam;
  i : Integer;
begin
  for i := 0 to FParams.Count - 1 do begin
    P := FParams[i];
    P.Free;
  end;
  FParams.Clear;
end;

function TAppParams.LoadFromStream(Stream: TStream): Boolean;
var s : AnsiString;
  i,c : Integer;
  P : TAppParam;
begin
  Result := false;
  InternalClear;
  if TStreamOp.ReadAnsiString(Stream,s)<0 then exit;
  if s<>CT_AppParams_File_Magic then raise Exception.Create('Invalid file type');
  Stream.Read(c,sizeof(c));
  for i := 0 to c-1 do begin
    P := TAppParam(TAppParam.NewInstance);
    P.FAppParams := Self;
    FParams.Add(P);
    if not P.LoadFromStream(Stream) then exit;
  end;
  Result := true;
end;

function TAppParams.Param(index: Integer): TAppParam;
begin
  Result := TAppParam(FParams[index]);
end;

procedure TAppParams.Save;
begin
  if Assigned(FParamsStream) then begin
    FParamsStream.Position := 0;
    FParamsStream.Size := 0;
    SaveToStream(FParamsStream);
  end;
end;

procedure TAppParams.SaveToStream(Stream: TStream);
var s : AnsiString;
  i : Integer;
begin
  s := CT_AppParams_File_Magic;
  TStreamOp.WriteAnsiString(Stream,s);
  i := FParams.Count;
  Stream.Write(i,sizeof(i));
  for i := 0 to FParams.Count - 1 do begin
    TAppParam(FParams[i]).SaveToStream(Stream);
  end;
end;

procedure TAppParams.SetFileName(const Value: AnsiString);
var fm : Word;
begin
  if FFileName=Value then exit;
  if Assigned(FParamsStream) then FParamsStream.Free;
  FParamsStream := nil;
  FFileName := Value;
  if Value<>'' then begin
    if FileExists(Value) then fm := fmOpenReadWrite
    else fm := fmCreate;

    FParamsStream := TFileStream.Create(Value,fm+fmShareExclusive);
    LoadFromStream(FParamsStream);
  end;
end;

initialization
  _appParams := nil;
end.
