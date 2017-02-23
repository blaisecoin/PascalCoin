{
  Copyright (c) 2016 by Albert Molina
  Copyright (c) 2017 by BlaiseCoin developers

  Distributed under the MIT software license, see the accompanying file LICENSE
  or visit http://www.opensource.org/licenses/mit-license.php.

  This unit is a part of BlaiseCoin, a P2P crypto-currency.
}

unit UConst;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface

Uses UOpenSSLdef;
{$I config.inc}


{$IFNDEF FPC}
  // See http://wiki.freepascal.org/Code_Conversion_Guide
type
  PtrInt = integer;
  PtrUInt = cardinal;
{$ENDIF}

Const
  CT_Genesis_Magic_String_For_Old_Block_Hash :
    AnsiString =
    '(c) Albert Molina - Genesis block at same time than BitCoin Block 424720 Hash 000000000000000001cc41ff7846264718ef0a15f97f532a98277bd5f6820b89';

  CT_Zero_Block_Proof_of_work_in_Hexa =
    {$IFDEF PRODUCTION}'00000003A29C32E84A539ADE24397D41D30116A6FAFEC17B7D9CED68A4238C92'{$ELSE}{$IFDEF TESTNET}''{$ELSE}{$ENDIF}{$ENDIF};


  CT_NetServer_Port = {$IFDEF PRODUCTION}9004{$ELSE}{$IFDEF TESTNET}9104{$ELSE}{$ENDIF}{$ENDIF};
  CT_JSONRPCMinerServer_Port = {$IFDEF PRODUCTION}9009{$ELSE}{$IFDEF TESTNET}9109{$ELSE}{$ENDIF}{$ENDIF};
  CT_JSONRPC_Port = {$IFDEF PRODUCTION}9003{$ELSE}{$IFDEF TESTNET}9103{$ELSE}{$ENDIF}{$ENDIF};
  CT_AccountsPerBlock = 5;

  CT_NewLineSecondsAvg: Cardinal = {$IFDEF PRODUCTION}300{$ELSE}{$IFDEF TESTNET}30{$ELSE}{$ENDIF}{$ENDIF};
    // 60*5=300 seconds -> 5 minutes avg
    //   -> 1 day = 86400 seconds -> 1 year = 31536000 seconds (aprox)
    //   Each year = 105120 new blocks (aprox)
    //   -> *5 accounts per block = 525600 new accounts each year (aprox)

  CT_FirstReward: UInt64 = 1000000; // 4 decimals... First reward = 100,0000
  CT_MinReward: UInt64 = 10000; // 4 decimals... Min reward = 1,0000
  CT_NewLineRewardDecrease: Cardinal = 420480; // Avg 4 year

  CT_WaitNewBlocksBeforeTransaction = 100;

  CT_RecoverFoundsWaitInactiveCount = 420480;  // After 4 years... if an account has no operations, money will be a reward for a miner!

  CT_MaxTransactionAmount = 1000000000000;
  CT_MaxTransactionFee = 100000000;
  CT_MaxWalletAmount = 10000000000000;
  //
  CT_MinCompactTarget: Cardinal = {$IFDEF PRODUCTION}$19000000{$ELSE}{$IFDEF TESTNET}$19000000{$ELSE}{$ENDIF}{$ENDIF}; // First compact target of block 0

  CT_CalcNewTargetBlocksAverage: Cardinal = 100;
  CT_MaxAccount : Cardinal = $FFFFFFFF;
  CT_MaxBlock : Cardinal = $FFFFFFFF;

  CT_MaxPayloadSize = 255; // Max payload size in bytes
  CT_MaxSecondsDifferenceOfNetworkNodes = 180; // 3 minutes. If a Node has a +- value difference, will be blacklisted

  CT_MinServersConnected = 3;
  CT_MaxServersConnected = 5;

  CT_MaxClientsConnected = 500;

  CT_BankToDiskEveryNBlocks = 100; // Build 1.5 changed from 500 to 100; // Build 1.3.0 Changed from 1000 to 500

  CT_Default_EC_OpenSSL_NID = NID_secp256k1;

  CT_BlockChain_Protocol_Version: Word = $0001; // Version 1
  CT_BlockChain_Protocol_Available: Word = $0001; // Build 1.4 Protocol available changed 0->1

  CT_MagicNetIdentification = $711A0F05; // Network magic

  // Build 1.0.4 - introducing NetProtocol versioning:
  CT_NetProtocol_Version: Word = $0004;
  // IMPORTANT NOTE!!!
  // NetProtocol_Available MUST BE always >= NetProtocol_version
  CT_NetProtocol_Available: Word = $0005;  // Remember, >= NetProtocol_version !!!

  CT_SafeBoxBankVersion : Word = 2;

  CT_MagicIdentificator: AnsiString = 'BlaiseCoin'; // Safebox magic

  // Value of Operations type in Protocol 1
  CT_Op_Transaction = $01;
  CT_Op_Changekey = $02;
  CT_Op_Recover = $03;

  CT_ClientAppVersion : AnsiString = {$IFDEF PRODUCTION}'1.0.1'{$ELSE}{$IFDEF TESTNET}'TESTNET 1.0.1'{$ELSE}{$ENDIF}{$ENDIF};

  CT_Discover_IPs =  'blaise1.ignorelist.com;blaise1.mooo.com;blaise1.qc.to;blaise1.strangled.net';

  CT_TRUE_FALSE : Array[Boolean] Of AnsiString = ('FALSE','TRUE');

  // App Params
  CT_PARAM_GridAccountsStream = 'GridAccountsStream';
  CT_PARAM_GridAccountsPos = 'GridAccountsPos';
  CT_PARAM_DefaultFee = 'DefaultFee';
  CT_PARAM_InternetServerPort = 'InternetServerPort';
  {$IFDEF TESTNET}CT_PARAM_AutomaticMineWhenConnectedToNodes = 'AutomaticMineWhenConnectedToNodes';{$ENDIF}
  CT_PARAM_MinerPrivateKeyType = 'MinerPrivateKeyType';
  CT_PARAM_MinerPrivateKeySelectedPublicKey = 'MinerPrivateKeySelectedPublicKey';
  CT_PARAM_SaveLogFiles = 'SaveLogFiles';
  CT_PARAM_SaveDebugLogs = 'SaveDebugLogs';
  CT_PARAM_ShowLogs = 'ShowLogs';
  CT_PARAM_MinerName = 'MinerName';
  CT_PARAM_FirstTime = 'FirstTime';
  CT_PARAM_ShowModalMessages = 'ShowModalMessages';
  {$IFDEF TESTNET}CT_PARAM_MaxCPUs = 'MaxCPUs'; {$ENDIF} //deprecated
  CT_PARAM_PeerCache = 'PeerCache';
  CT_PARAM_TryToConnectOnlyWithThisFixedServers = 'TryToConnectOnlyWithFixedServers';
  CT_PARAM_JSONRPCMinerServerPort = 'JSONRPCMinerServerPort';
  CT_PARAM_JSONRPCMinerServerActive = 'JSONRPCMinerServerActive';
  CT_PARAM_JSONRPCEnabled = 'JSONRPCEnabled';
  CT_PARAM_JSONRPCAllowedIPs = 'JSONRPCAllowedIPs';



implementation

end.