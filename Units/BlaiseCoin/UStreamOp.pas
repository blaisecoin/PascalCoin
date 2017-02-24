{
  Copyright (c) 2016 by Albert Molina
  Copyright (c) 2017 by BlaiseCoin developers

  Distributed under the MIT software license, see the accompanying file LICENSE
  or visit http://www.opensource.org/licenses/mit-license.php.

  This unit is a part of BlaiseCoin, a P2P crypto-currency.
}

unit UStreamOp;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface

uses
  SysUtils, Classes;

type
  TStreamOp = class
  public
    class function ReadAnsiString(Stream: TStream; var Value: AnsiString): Integer;
    class function WriteAnsiString(Stream: TStream; Value: AnsiString): Integer;
  end;

  EStreamOp = class(Exception);

implementation

uses
  ULog;

{ TStreamOp }

class function TStreamOp.ReadAnsiString(Stream: TStream; var Value: AnsiString): Integer;
var
  l: Word;
begin
  if Stream.Size - Stream.Position < 2 then
  begin
    // no size word
    Value := '';
    Result := -1;
    exit;
  end;
  Stream.Read(l, 2);
  if Stream.Size - Stream.Position < l then
  begin
    Stream.Position := Stream.Position - 2; // Go back!
    Value := '';
    Result := -2;
    exit;
  end;
  SetLength(Value, l);
  if l > 0 then
    Stream.ReadBuffer(Value[1], l);
  Result := l;
end;

class function TStreamOp.WriteAnsiString(Stream: TStream; Value: AnsiString): Integer;
var
  n: Integer;
  l: Word;
  e: String;
begin
  n := Length(Value);
  if n > $FFFF then
  begin
    e := 'String too long to stream, length=' + IntToStr(n);
    TLog.NewLog(lterror, ClassName, e);
    raise EStreamOp.Create(e);
  end;
  l := n;
  Stream.Write(l, 2);
  if l > 0 then
    Stream.WriteBuffer(Value[1], l);
  Result := l;
end;

end.
