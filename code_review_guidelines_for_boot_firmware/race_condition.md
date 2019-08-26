<!--- @file
  race-condition.md for EDK II Secure Code Review Guide

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

## Race Condition {#race-condition}

There are two typical race conditions found in firmware:

 1.  Race condition in a data buffer
 2.  Race condition in a register unlocking mechanism.

**Previous Vulnerabilities:**

### Race condition for data buffer {#race-condition-for-data-buffer}

The typical example is the SMM communication buffer. If the check function verified the non-SMRAM copy of communication buffer and then uses it, the attacker may use another CPU thread to perform Time-of-Check/Time-of-Use (TOC/TOU) attack to modify the buffer content after it is checked.

To mitigate this, the communication buffer must be copied into SMRAM before it is checked.

The other example is the Flash Update code. In [BlackHat 2019](http://i.blackhat.com/USA-19/Thursday/us-19-Matrosov-Breaking-Through-Another-Side-Bypassing-Firmware-Security-Boundaries-From-Embedded-Controller.pdf), a Thinkpad EC update driver issue is exposed. The signature check and verification are separated.

To mitigate this, both verification and update must happen together in an isolated execution environment or before 3rd part code running.

Another example is the motherboard flash content. When [Intel Boot Guard](https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/security-technologies-4th-gen-core-retail-paper.pdf) is enabled, the Authenticated Code Module (ACM) loads Initial Boot Block (IBB) flash into cache and validates the cached copy. An attacker may use the flash programmer to update the IBB flash copy after it is loaded by ACM. This is a variation of a Time-of-Check/Time-of-Use attack.

The IBB cache copy mechanism needs to ensure that no code or data in the IBB flash can be referenced.

### Race condition for register unlock {#race-condition-for-register-unlock}

In 2014, MITRE found a race condition, named [Speed Racer](https://fahrplan.events.ccc.de/congress/2014/Fahrplan/system/attachments/2565/original/speed_racer_whitepaper.pdf), which allows an attacker to subvert a component of the firmware flash protection mechanisms.

Secure code review must verify that SMM code does not leave threads outside of SMRAM when there is flash protection is in an unlocked state.