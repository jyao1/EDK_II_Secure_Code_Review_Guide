<!--- @file
  secret-handling.md for EDK II Secure Code Review Guide

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

## Secret Handling {#secret-handling}

In some cases, the users are required to input passwords in the firmware, such as setup administrator password, hard drive password, and Trusted Computing Group (TCG) OPAL password. Sometimes the firmware also includes some password or access key. We need a good way to handle these secrets.

**Previous Vulnerabilities:**

### Password not cleared in memory {#password-not-cleared-in-memory}

In [DefCon 2008](https://www.defcon.org/images/defcon-16/dc16-presentations/brossard/defcon-16-brossard-wp.pdf), iViZ disclosed a way to get the password from the BIOS Data Area (BDA) because the BIOS does not clear the keyboard buffer which contains the password information.

After the password is used, the code should always clear it in its various locations: input key buffer, stack, heap, global variable, etc.

### Key based protection {#key-based-protection}

In [BlackHat 2019](http://i.blackhat.com/asia-19/Fri-March-29/bh-asia-Matrosov-Modern-Secure-Boot-Attacks.pdf), Mastrov disclosed how to brute force search Computrace disable key in SMRAM. The key comparison algorithm does not have a constant time. Also, the final key is only 1 byte. See the statement using `key_match` below.



```
key_byte = cpu_regs->EBX;
ComputraceState.Active = TRUE;
ComputraceState.DisableSecreteKey[0] = key_byte & 0xff;
ComputraceState.DisableSecreteKey[1] = (key_byte & 0xff00) >> 8;
ComputraceState.DisableSecreteKey[2] = (key_byte & 0xff0000) >> 16;
ComputraceState.DisableSecreteKey[3] = (key_byte & 0xff000000) >> 24;

key_match = TRUE;
for (i = 0; i < 4; i) {
  if (key[i] != ComputraceState.DisableKey[i]) {
    key_match = FALSE;
    break;
  }
}
```




This is a vulnerable inside channel attack. The duration of the verification then reveals the index of the character. The code should always use a mechanism that compares the entire data before completion. Note a single-byte key is vulnerable to brute force attack.

### Default key {#default-key}

In [BlackHat 2011](https://media.blackhat.com/bh-us-11/Miller/BH_US_11_Miller_Battery_Firmware_Public_Slides.pdf), Accuvant Lab disclosed a way to access battery firmware because the access key is unchanged. The below disassembly code shows the 0x36720414 is hardcoded. It is also the default unseal key in a public document. See statements below moving constants into `edx`


```
UnSeal_LSW:
xor eax, eax
mov edx, 0414h
call writeSBWord
test eax, eax
jz short UnSeal_MSW
...
UnSeal_MSW:
xor eax, eax
mov edx, 3672h
call writeSBWord
test eax, eax
jz short loc_26FD
```




The vendor should always change the default password or key for a device to prevent illegal access. Also, it is not a good idea to hardcode the key in the source code.

Another example in TPM2, during boot, the platform should always send Tpm2HierarchyChangeAuth(TPM_RH_PLATFORM) command to a TPM2 device to prevent other code accessing the TPM2 platform hierarchy. The same action must be done in S3 resume too.


### Static unlock password {#static-unlock-password}

In [BlackHat 2019](http://i.blackhat.com/USA-19/Thursday/us-19-Matrosov-Breaking-Through-Another-Side-Bypassing-Firmware-Security-Boundaries-From-Embedded-Controller.pdf), Mastrov disclosed Thinkpad EC shared the secret sent from the BIOS.



```
op3 = 0x14;
op2 = 0xA;
op1 = 2;
*buffer = 0x6065845A; // static unlock password
buffer[4] = 0x47;
buffer_size = 5;
LOBYTE(res) = EcIoDxeInterface->CpuIoCmdWriteBufferEC1(
               EcIoDxeInterface,
               *&op1,
               *&op2,
               *&op3,
               *&buffer_size,
               buffer);
```


