 <!--- @file
  external-input.md for EDK II Secure Code Review Guide

  Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>

  Redistribution and use in source (original document form) and 'compiled'
  forms (converted to PDF, epub, HTML and other formats) with or without
  modification, are permitted provided that the following conditions are met:

  1) Redistributions of source code (original document form) must retain the
     above copyright notice, this list of conditions and the following
     disclaimer as the first lines of this file unmodified.

  2) Redistributions in compiled form (transformed to other DTDs, converted to
     PDF, epub, HTML and other formats) must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.

  THIS DOCUMENTATION IS PROVIDED BY TIANOCORE PROJECT "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
  EVENT SHALL TIANOCORE PROJECT  BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION, EVEN IF
  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

-->




## External Input {#external-input}

External input describes data that can be controlled by an attacker. Examples include:

*   UEFI capsule image
*   Boot logo in Bitmap (BMP) or Joint Photographic Experts Group (JPEG) format
*   Contents of file system partitions
*   Read/write variables
*   System Management Mode (SMM) communication buffer
*   Network packets

**Previous Vulnerabilities:**

### Boot Logo Image {#boot-logo-image}

[At BlackHat 2009](https://www.blackhat.com/presentations/bh-usa-09/WOJTCZUK/BHUSA09-Wojtczuk-AtkIntelBios-SLIDES.pdf), Invisible Things Lab demonstrated how to use a buffer overflow in BMP file processing to construct an attack and flash a new firmware. The BMP file is an external input where an attacker may input a large value for `PixelWidth` and `PixelHeight`. This causes `BltBufferSize` to overflow and results in a very small number. This is a typical integer overflow caused by multiplication.



```
EFI_STATUS ConvertBmpToGopBlt ()
{
 /// ...
  if (BmpHeader->CharB != 'B' || BmpHeader->CharM != 'M') {
    return EFI_UNSUPPORTED;
  }
  BltBufferSize = BmpHeader->PixelWidth * BmpHeader->PixelHeight
                    * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL);
  IsAllocated = FALSE;
  if (*GopBlt == NULL) {
    *GopBltSize = BltBufferSize;
    *GopBlt = EfiLibAllocatePool (*GopBltSize);
```



To handle these cases, code should check for integer overflow using division, as shown below:



```
if (BmpHeader-&gt;PixelWidth &gt; MAX_UINT / sizeof 
(EFI_GRAPHICS_OUTPUT_BLT_PIXEL) / BmpHeader-&gt;PixelHeight) {
    return EFI_INVALID_PARAMETER;

}
```



### SMM Callout {#smm-callout}

At [Black Hat DC 2009](https://www.blackhat.com/presentations/bh-dc-09/Wojtczuk_Rutkowska/BlackHat-DC-09-Rutkowska-Attacking-Intel-TXT-slides.pdf), Invisible Things Lab demonstrated a way to inject code into SMM. The SMM code referenced (``ACPINV`` below) a function pointer in Advanced Configuration and Power Interface (ACPI) Non-Volatile Storage (NVS) memory and invoked this function address. An attacker may modify the function pointer address in ACPI NVS so it points to a malicious function.





```
mov [ACPINV+x], %rax
call *0x18(%rax)

```



A similar issue is also found in [ThinkPad 2016](http://blog.cr4.sh/2016/06/exploring-and-exploiting-lenovo.html). The `SmmRuntimeCallHandle` is the pointer in ACPI Reserved memory. As such, the attacker may replace this function pointer with any address. 

This is shown in line with the statement:  `RtServices = (EFI_SMM_RT_CALLBACK_SERVICES *) SmmRtStruct->PrivateData.SmmRuntimeCallHandle;` below.






```
EFI_STATUS
EFIAPI
SmmRuntimeManagementCallback (
  IN EFI_HANDLE             SmmImageHandle,
  IN OUT VOID               *CommunicationBuffer,
  IN OUT UINTN              *SourceSize
  )
{
  SMM_RUNTIME_COMMUNICATION_STRUCTURE *SmmRtStruct;
  EFI_SMM_RT_CALLBACK_SERVICES        *RtServices;

  RtServices  = NULL;

  SmmRtStruct = (SMM_RUNTIME_COMMUNICATION_STRUCTURE *) CommunicationBuffer;
  RtServices  = (EFI_SMM_RT_CALLBACK_SERVICES *) SmmRtStruct->PrivateData.SmmRuntimeCallHandle;

  if (RtServices != NULL) {
    RtServices->CallbackFunction (RtServices->Context, mSmst, (VOID *) &SmmRtStruct->PrivateData);
    SmmRtStruct->PrivateData.SmmRuntimeCallHandle = NULL;
  }

  return EFI_SUCCESS;
}

```





It is critical that SMM never reference memory outside System Management RAM (SMRAM) for function pointers.

In the latest Intel processors, the SMM_Code_Access_Chk feature can be used to block code execution outside of the value set by the SMRAM Range Register (SMRR). This feature MUST be enabled if it is supported.

The latest versions of EDK II also enable Executable Disable (XD) for memory addresses outside of SMRAM.

### SMM Communication {#smm-communication}

In [CanSecWest 2015](http://www.c7zero.info/stuff/ANewClassOfVulnInSMIHandlers_csw2015.pdf), a new class of SMM attack was disclosed. The attacker may construct a SMM 
communication buffer that points to memory owned by System Management RAM (SMRAM) or Virtual Machine Monitor (VMM), then pass this address into a System Management Interrupt 
(SMI) handler. This causes the SMI handler to perform the write for the attacker. This typically classified as a “confused deputy” attack. See the lines with `CommBuffer` 
and with the  `CopyMem` statement below.






```
SmmVariableHandler ()
//  ...
  SmmVariableFunctionHeader = (SMM_VARIABLE_COMMUNICATE_HEADER *)CommBuffer;
  switch (SmmVariableFunctionHeader->Function) {
  case SMM_VARIABLE_FUNCTION_GET_VARIABLE:
    SmmVariableHeader = (SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE *)
    SmmVariableFunctionHeader->Data;
    Status = VariableServiceGetVariable (
               ...
               (UINT8 *)SmmVariableHeader->Name + SmmVariableHeader->NameSize
               );
}

VariableServiceGetVariable (
  // ...
  OUT VOID *Data
  )
{
 // ...
  CopyMem (Data, GetVariableDataPtr (Variable.CurrPtr), VarDataSize);
}

```


To mitigate this attack, the SMI handler is required to use the library service `SmmIsBufferOutsideSmmValid()` to check the communication buffer before accessing it.

ACPI table for Authenticated Code Module (ACM) is a signed binary module delivered by Intel. It is used to construct a dynamic root of trust for measurement (DRTM) 
environment. In 2011, Invisible Things Lab disclosed [a way to hijack the SINIT ACM](https://invisiblethingslab.com/resources/2011/Attacking_Intel_TXT_via_SINIT_hijacking.pdf). 
The issue happens when the ACM code parses the untrusted ACPI DMA Remapping (DMAR) table. The DMAR table is used before validation of the address. As such the attacker may 
control the copied memory length and override the Intel Trusted Executable Technology (TXT) heap and SINIT ACM itself. See line `6741` below.





```
6675: mov  (%edi),%esi
6677: cmpl $0x52414d44,(%esi)
; (DWORD*)esi == ’DMAR’?

667d: je 0x6697
...
6697: mov  (%edi),%edi
6699: mov  %edi,%es:0xa57
; var_a57 = &dmar

66a0: mov  0x4(%edi),%ecx
; ecx = dmar.len

66a3: push %ecx
66a4: add  %edi,%ecx
66a6: mov  %ecx,%es:0xa5b
; var_a5b = &dmar + dmar.len

...
6701: mov  %es:0xa47,%edi
; edi = var_a47 (memory on the TXT heap)

6708: mov  (%edi),%eax
670a: mov  %es:0xa5b,%ebx
; ebx = &dmar + dmar.len

6711: sub %es:0xa57,%ebx
; ebx = dmar.len

...
6738: mov %es:0xa57,%esi
; var_a57 = &dmar

673f: mov %ebx, %ecx
6741: rep movsb %ds:(%esi),%es:(%edi)
; memcpy (var_a47, dmar, dmar.len)
```






Adding a check for the length field of untrusted data source is mandatory.

### Capsule Image {#capsule-image}

Most UEFI firmware supports capsule based firmware update. In 2014, MITRE demonstrated how to use [a vulnerability in the capsule coalesce process](https://www.mitre.org/sites/default/files/publications/14-2221-extreme-escalation-presentation.pdf) to attack the firmware update process.

This is another example of an integer overflow. **NOTE**: `MemorySize if` statement and `Size +=` below.






```
EFI_STATUS
EFIAPI
CapsuleDataCoalesce (
  IN EFI_PEI_SERVICES                **PeiServices,
  IN EFI_PHYSICAL_ADDRESS            *BlockListBuffer,
  IN MEMORY_RESOURCE_DESCRIPTOR      *MemoryResource,
  IN OUT VOID                        **MemoryBase,
  IN OUT UINTN                       *MemorySize
  )
{
  //...
    if (*MemorySize <= (CapsuleSize + DescriptorsSize)) {
      return EFI_BUFFER_TOO_SMALL;
  }
  //...
}

EFI_STATUS
GetCapsuleInfo (
  IN EFI_CAPSULE_BLOCK_DESCRIPTOR   *Desc,
  IN OUT UINTN                      *NumDescriptors OPTIONAL,
  IN OUT UINTN                      *CapsuleSize OPTIONAL,
  IN OUT UINTN                      *CapsuleNumber OPTIONAL
  )
{
//  ...
    } else {
      Size += (UINTN) Desc->Length;
      Count++;
  ...
}
```




Before the code performs the addition, the code must use subtraction to check if the addition will cause an integer overflow.

### Read/Write Variable {#read-write-variable}

A read/write variable is another potential attack surface because it is easily controlled by an attacker. In [CanSecWest 2014](https://cansecwest.com/slides/2014/AllYourBoot_csw14-mitre-final.pdf), MITRE demonstrated how to modify the “Setup” variable to bypass UEFI secure boot ImageVerificationPolicy.

The attack taught us that it is a bad idea to embed security policy in a read/write “Setup” variable.

### S3 Boot Script {#s3-boot-script}

The S3 Boot Script is used to restore the register settings during the ACPI S3 resume process. In [CanSecWest 2015](https://cansecwest.com/slides/2015/AttacksOnUEFI_Rafal.pptx), Invisible Things Lab found some firmware implementations did not protect the S3 script or the dispatch function code, so it remained in an OS-accessible ACPI memory region. This allowed an attacker to inject malicious boot script content to bypass the silicon lock register setting in the S3 Boot Script.  
See the use of `EntryFunc`  and `EntryPoint` below.






```
BootScriptExecuteDispatch (IN UINT8 *Script)
{
   ...
   EntryFunc = (DISPATCH_ENTRYPOINT_FUNC) (UINTN) (ScriptDispatch.EntryPoint);
   Status = EntryFunc (NULL, NULL);
}

```



As a mitigation, the lockbox should be used to protect data used in the S3 resume phase.

### Network for AMT {#network-for-amt}

[Intel® Active Management Technology](https://www.intel.com/content/www/us/en/architecture-and-technology/intel-active-management-technology.html) (Intel® AMT) is a remote management feature in the Intel vPRO platform. In 2017, Embed disclosed [an issue with Intel AMT](https://www.blackhat.com/docs/us-17/thursday/us-17-Evdokimov-Intel-AMT-Stealth-Breakthrough.pdf) where providing an empty response will cause password verification to succeed as if the attacker provided the admin password. 
See the use of `strncmp` and `response.length` below.





```
/* NETSTACK_CODE:20431FC8 */

if(strncmp(computed_response, response.value, response.length))
{
   goto error;
}
return 0;
```






To avoid similar issues, network packet processing code should always be carefully reviewed.

### Network for BMC {#network-for-bmc}

In [SSTIC 2018](https://www.sstic.org/media/SSTIC2018/SSTIC-actes/subverting_your_server_through_its_bmc_the_hpe_ilo/SSTIC2018-Slides-subverting_your_server_through_its_bmc_the_hpe_ilo4_case-gazet_perigaud_czarny.pdf), [BlackHat 2018](http://i.blackhat.com/us-18/Wed-August-8/us-18-Waisman-Soler-The-Unbearable-Lightness-of-BMC.pdf), researchers disclosed multiple security issues in baseboard management controller, or BMC.

One issue is sscanf(). This is unsafe function and causes buffer overflow.

```
else if (!strnicmp (request, http_header, "Connection :", 0xBu))
{
  sscanf (http_header, "%*s %s", https_connection->connection);
}

struct https_connection {
  ...
  0x0C : char connection [0x10];
  ...
  0x28 : char localConnection;
  ...
  0xB8 : void * vtable;
}
```

The banned function is dangerous and must not be used.

The other buffer overflow issue is triggered before the signature verification. As such, the signature verification can be bypassed.


```
char line_local [1024];
while (1) {
  if ( !readline(dlobj, line_local) ) /* HERE */
    return 0xB;
  if ( !strcmp(line_local , "--=</End HP Signed File Fingerprint\\>=--") )
    break;
  key = split(line_local , ":");
  if ( !key ) return 1;
  if ( !strcmp(key, "Hash") )
    some_stuff();
  else if ( !strcmp(key, "Signature") )
    some_other_stuff();
}

int readline(DOWNLOADER *dlobj , char *line_out)
{
  char *ptr;
  int line_size;
  ptr = strtok(dlobj ->buffer_read , "\r\n");
  if ( ptr )
  {
    line_size = ptr - dlobj ->buffer_read;
    if ( line_out )
    {
      memcpy(line_out, dlobj->buffer_read, line_size); /* BAD */
      line_out[line_size] = 0;
    }
  [...]
}
```

To avoid such issues, the input data size must be carefully checked.

