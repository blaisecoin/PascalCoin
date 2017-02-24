{
  Copyright (c) 2016 by Albert Molina
  Copyright (c) 2017 by BlaiseCoin developers

  Distributed under the MIT software license, see the accompanying file LICENSE
  or visit http://www.opensource.org/licenses/mit-license.php.

  This unit is a part of BlaiseCoin, a P2P crypto-currency.
}

unit UTime;

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
  SysUtils;

{$IFnDEF FPC}
function TzSpecificLocalTimeToSystemTime(lpTimeZoneInformation: PTimeZoneInformation; var lpLocalTime, lpUniversalTime: TSystemTime): BOOL; stdcall;
function SystemTimeToTzSpecificLocalTime(lpTimeZoneInformation: PTimeZoneInformation; var lpUniversalTime,lpLocalTime: TSystemTime): BOOL; stdcall;
{$ENDIF}

function DateTime2UnivDateTime(d:TDateTime):TDateTime;
function UnivDateTime2LocalDateTime(d:TDateTime):TDateTime;

function UnivDateTimeToUnix(dtDate: TDateTime): Longint;
function UnixToUnivDateTime(USec: Longint): TDateTime;

function UnixTimeToLocalElapsedTime(USec : Longint) : AnsiString;
function DateTimeElapsedTime(dtDate : TDateTime) : AnsiString;

implementation

{$IFDEF FPC}
uses DateUtils;
{$ELSE}
function TzSpecificLocalTimeToSystemTime; external 'kernel32.dll' name 'TzSpecificLocalTimeToSystemTime';
function SystemTimeToTzSpecificLocalTime; external kernel32 name 'SystemTimeToTzSpecificLocalTime';
{$ENDIF}

const
    UnixStartDate: TDateTime = 25569.0; // 01/01/1970

function UnixTimeToLocalElapsedTime(USec : Longint) : AnsiString;
var diff, positivediff : Longint;
Begin
  diff := UnivDateTimeToUnix(DateTime2UnivDateTime(now)) - Usec;
  if diff<0 then positivediff := diff * (-1)
  else positivediff := diff;
  if positivediff<60 then Result := inttostr(diff)+' seconds ago'
  else if positivediff<(60*2) then Result := '1 minute ago'
  else if positivediff<(60*60) then Result := inttostr(diff div 60)+' minutes ago'
  else if positivediff<(60*60*2) then Result := '1 hour ago'
  else if positivediff<(60*60*24) then Result := inttostr(diff div (60*60))+' hours ago'
  else Result := inttostr(diff div (60*60*24))+' days ago';
End;

function DateTimeElapsedTime(dtDate : TDateTime) : AnsiString;
Begin
  Result := UnixTimeToLocalElapsedTime( UnivDateTimeToUnix(DateTime2UnivDateTime(dtDate)) );
End;

function DateTime2UnivDateTime(d:TDateTime):TDateTime;
{$IFDEF FPC}
begin
  Result := UniversalTimeToLocal(d);
//  Result := LocalTimeToUniversal(d);
end;
{$ELSE}
var
 TZI:TTimeZoneInformation;
 LocalTime, UniversalTime:TSystemTime;
begin
  GetTimeZoneInformation(tzi);
  DateTimeToSystemTime(d,LocalTime);
  TzSpecificLocalTimeToSystemTime(@tzi,LocalTime,UniversalTime);
  Result := SystemTimeToDateTime(UniversalTime);
end;
{$ENDIF}

function UnivDateTime2LocalDateTime(d:TDateTime):TDateTime;
{$IFDEF FPC}
begin
//  Result := UniversalTimeToLocal(d);
  Result := LocalTimeToUniversal(d);
end;

{$ELSE}
var
 TZI:TTimeZoneInformation;
 LocalTime, UniversalTime:TSystemTime;
begin
  GetTimeZoneInformation(tzi);
  DateTimeToSystemTime(d,UniversalTime);
  SystemTimeToTzSpecificLocalTime(@tzi,UniversalTime,LocalTime);
  Result := SystemTimeToDateTime(LocalTime);
end;
{$ENDIF}

function UnivDateTimeToUnix(dtDate: TDateTime): Longint;
begin
  Result := Round((dtDate - UnixStartDate) * 86400);
end;

function UnixToUnivDateTime(USec: Longint): TDateTime;
begin
  Result := (Usec / 86400) + UnixStartDate;
end;

end.
