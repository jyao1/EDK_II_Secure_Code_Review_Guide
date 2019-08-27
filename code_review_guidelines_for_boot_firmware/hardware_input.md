<!--- @file
  hardware-input.md for EDK II Secure Code Review Guide

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

## Hardware Input {#hardware-input}

Hardware input is a special class of external input. If an attacker controls hardware, the input from hardware is considered to be untrusted. This includes, but is not limited to, Memory Mapped Input/Output (MMIO), cache, Direct Memory Access (DMA), Universal Serial Bus (USB) descriptors, and Bluetooth Low Energy (BLE) advertisement data.

**Previous Vulnerabilities:**

### MMIO BAR Overlap {#mmio-bar-overlap}

In [BlackHat 2008](https://invisiblethingslab.com/resources/bh08/part2-full.pdf), Invisible Things Lab demonstrated how to program the remap Base Address Register (BAR) to make the remap memory overlap with VMM or SMRAM, thus allowing for subsequent modification of the VMM or SMRAM contents.

```
pci_write_word (dev, TOUUD_OFFSET, (new_remap_limit+1)&lt;&lt;6);
pci_write_word (dev, REMAP_BASE_OFFSET, new_remap_base);
pci_write_word (dev, REMAP_LIMIT_OFFSET, new_remap_limit);
```

In [BlackHat 2009](https://invisiblethingslab.com/resources/bh09usa/Ring%20-3%20Rootkits.pdf), Invisible Tings Lab also found the remap register bar can make the remap memory overlap with Management Engine (ME) RAM, thus allowing for a modification of the contents in ME firmware.

To mitigate this class of attack, verify register bars are properly locked

### MMIO BAR Access {#mmio-bar-access}

In [RECon 2017](http://www.c7zero.info/stuff/REConBrussels2017_BARing_the_system.pdf), Intel disclosed the MMIO BAR access issue in SMM. The attacker may configure the MMIO BAR to make it overlap with SMRAM. After this, subsequent access to MMIO in SMM becomes accesses to SMRAM.
See statements with `bar` assignment within `if` statement below.


```

static void mainboard_smi_brightness_down (void)
{
  u8 *bar;
  if ((bar = (u8 *)pci_read_config32(PCI_DEV(1, 0, 0), 0x18))) {
    printk(BIOS_DEBUG, “bar: %08X, level %02X\n”, (unsigned int)bar,
    *(bar+LVTMA_BL_MOD_LEVEL) &amp;= 0xf0;
    if (*(bar+LVTMA_BL_MOD_LEVEL) &gt; 0x10)
      *(bar+LVTMA_BL_MOD_LEVEL) -= 0x10;
  }
}
```





There are several ways for firmware to mitigate this class of attack. For example, SMM can verify the MMIO bar does not overlap with SMRAM or is not in DRAM before access. SMM can revert the MMIO bar value to the default setting, perform an operation, then restore it to the original value.

Care must be taken when code checks the MMIO. In 2009, Invisible Things Lab showed an [incorrect check for MMIO BAR](https://invisiblethingslab.com/resources/misc09/Another%20TXT%20Attack.pdf). This code checks the Memory Controller Hub (MCH) BAR value, but only for the lower 32 bits. Since the MCH BAR is 36 bits, the attacker may configure the MCH BAR value above 4G and exploit ACM due to the error in validation. This can results in an improper setup for the Intel® Virtualization Technology for Direct I/O (Intel® VT-d) engine. 
See the usage of `MCHBAR address` below



```
pusha
mov eax, 0x48 ; MCHBAR address
call pci_get_long
and ebx, 0xfffffffe
mov DWORD PTR es:MCHBAR, ebx
cmp ebx, 0xfec04000
ja continue
mov al, 0x4
mov ah, 0xc
call sinit_error
continue:
or ebx, 0x1
call pci_write_long
popa
ret
```





### Cache {#cache}

In [CanSecWest 2009](https://cansecwest.com/csw09/csw09-duflot.pdf), Cache poisoning was used to attack SMRAM in 2009\. The attacker modifies the Memory Type Range Register (MTRR) to make it overlap with SMRAM, then updates the SMRAM cache and triggers an SMI.

Recent Intel processors have introduced the SMRAM Range Register (SMRR) to resist cache poison attack. SMRR must be setup for all logical processors. This prevents the MTRR overlap with SMRAM from taking effect.

### DMA {#dma}

In [BlackHat 2013](https://media.blackhat.com/us-13/US-13-Sevinsky-Funderbolt-Adventures-in-Thunderbolt-DMA-Attacks-Slides.pdf), the NCC group demonstrated a DMA attack using Thunderbolt. In 2017, OS password theft was demonstrated using [PCIleech](http://blog.frizk.net/2017/01/attacking-uefi-and-linux.html) hardware.

DMA attacks can be mitigated by setting up the Input/Output Management Unit (IOMMU) to block DMA access to full system memory. In firmware, this can be achieved using the IOMMU or disabling the Peripheral Component Interconnection (PCI) Bus Master Enable (BME) bit. However, if an untrusted device driver requires PCI BME access, the IOMMU must be setup to accommodate the untrusted device.

In [CanSecWest 2017](https://cansecwest.com/slides/2017/CSW2017_Cuauhtemoc-Rene_CPU_Hot-Add_flow.pdf), Intel disclosed a special attack for CPU hot-add process on server platform. The attacker uses DMA to tamper the code to be executed in the first SMI (at 0x3000:0x8000) by the newly-added CPU in order to perform SMBASE relocation.

To mitigate this, BIOS leverages existing HW protection mechanism in Intel CPUs against rogue DMA engines: GENPROTRANGE register programming.

### USB {#usb}

Because attackers can create devices with bad USB descriptors, USB data is considered untrusted. Projects like [Facedancer](http://goodfet.sourceforge.net/hardware/facedancer21/) are good examples of USB fuzzing tools. In [BlackHat 2014](https://www.blackhat.com/docs/eu-14/materials/eu-14-Schumilo-Dont-Trust-Your-USB-How-To-Find-Bugs-In-USB-Device-Drivers.pdf), a demo shows how to do fuzz for the USB device driver.

USB firmware drivers must assume USB descriptors are untrustworthy and always verify before consumption. This policy should also be applied to other drivers that consume potentially untrustworthy data, such as Bluetooth device advertisement messages.

### TPM Genie {#tpm-genie}

In 2018, the NCC group demonstrated that a [Trusted Platform Module (TPM) Genie](https://github.com/nccgroup/TPMGenie/blob/master/docs/CanSecWest_2018_-_TPM_Genie_-_Jeremy_Boone.pdf) may cause memory corruption in different TPM stacks, including Linux, tboot, and UEFI. This is possible when data returned by the TPM is not validated by the TPM stack.  See the usage of `recd` in the statements below.


```
int tpm_get_random(u32 chip_num, u8 *out, size_t max) {
  struct tpm_chip *chip;
  struct tpm_cmd_t tpm_cmd;
  u32 recd, num_bytes = min_t(u32, max, TPM_MAX_RNG_DATA);
  ...
  tpm_cmd.header.in = tpm_getrandom_header;
  tpm_cmd.params.getrandom_in.num_bytes = cpu_to_be32(num_bytes);
  err = tpm_transmit_cmd( chip, &amp;tpm_cmd,
  TPM_GETRANDOM_RESULT_SIZE + num_bytes );
  ...
  recd = be32_to_cpu(tpm_cmd.params.getrandom_out.rng_data_len);
  memcpy(out, tpm_cmd.params.getrandom_out.rng_data, recd);
  ...
}

```


As mitigation, the TPM driver must perform robust checks of the response buffer size.

### Glitch {#glitch}

In [BlackHat 2015](https://www.blackhat.com/docs/eu-15/materials/eu-15-Giller-Implementing-Electrical-Glitching-Attacks.pdf), NCC group demonstrated how to use glitch attack to break Xbox 360 bootloader security.

In [BlackHat 2018](http://i.blackhat.com/us-18/Wed-August-8/us-18-Milburn-There-Will-Be-Glitches-Extracting-And-Analyzing-Automotive-Firmware-Efficiently.pdf), Riscure used glitch to inject fault to break the Electronic Control Unit (ECU) found in cars.

To mitigate glitch attack, the possible hardware ways are: use memory integrity (e.g. ECC), remove debug interface. The possible software ways are: add redundancy (duplicated check/code), use control flow integrity, add random delay.


