program BlaiseCoinWallet;

uses
  Forms,
  UBlockChain in 'Units\BlaiseCoin\UBlockChain.pas',
  UCrypto in 'Units\BlaiseCoin\UCrypto.pas',
  UTime in 'Units\BlaiseCoin\UTime.pas',
  UWalletKeys in 'Units\BlaiseCoin\UWalletKeys.pas',
  UOpTransaction in 'Units\BlaiseCoin\UOpTransaction.pas',
  UNetProtocol in 'Units\BlaiseCoin\UNetProtocol.pas',
  UAccounts in 'Units\BlaiseCoin\UAccounts.pas',
  UConst in 'Units\BlaiseCoin\UConst.pas',
  UThread in 'Units\BlaiseCoin\UThread.pas',
  ULog in 'Units\BlaiseCoin\ULog.pas',
  UNode in 'Units\BlaiseCoin\UNode.pas',
  UECIES in 'Units\BlaiseCoin\UECIES.pas',
  UFRMWallet in 'Units\Forms\UFRMWallet.pas' {FRMWallet},
  UFolderHelper in 'Units\Utils\UFolderHelper.pas',
  UAppParams in 'Units\Utils\UAppParams.pas',
  UGridUtils in 'Units\Utils\UGridUtils.pas',
  UFRMPascalCoinWalletConfig in 'Units\Forms\UFRMPascalCoinWalletConfig.pas' {FRMPascalCoinWalletConfig},
  UFRMAbout in 'Units\Forms\UFRMAbout.pas' {FRMAbout},
  UFRMOperation in 'Units\Forms\UFRMOperation.pas' {FRMOperation},
  UFRMWalletKeys in 'Units\Forms\UFRMWalletKeys.pas' {FRMWalletKeys},
  UFRMNewPrivateKeyType in 'Units\Forms\UFRMNewPrivateKeyType.pas' {FRMNewPrivateKeyType},
  UFRMPayloadDecoder in 'Units\Forms\UFRMPayloadDecoder.pas' {FRMPayloadDecoder},
  UFRMNodesIp in 'Units\Forms\UFRMNodesIp.pas' {FRMNodesIp},
  UTCPIP in 'Units\BlaiseCoin\UTCPIP.pas',
  UJSONFunctions in 'Units\Utils\UJSONFunctions.pas',
  URPC in 'Units\BlaiseCoin\URPC.pas',
  UPoolMining in 'Units\BlaiseCoin\UPoolMining.pas',
  UFileStorage in 'Units\BlaiseCoin\UFileStorage.pas',
  UOpenSSL in 'Units\BlaiseCoin\UOpenSSL.pas',
  UOpenSSLdef in 'Units\BlaiseCoin\UOpenSSLdef.pas',
  UAES in 'Units\BlaiseCoin\UAES.pas',
  UStreamOp in 'Units\BlaiseCoin\UStreamOp.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.Title := 'BlaiseCoin Wallet, Miner & Explorer';
  Application.CreateForm(TFRMWallet, FRMWallet);
  Application.Run;
end.
