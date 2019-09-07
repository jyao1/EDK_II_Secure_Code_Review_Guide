<!--- @file
  cryptography.md for EDK II Secure Code Review Guide

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

## Cryptography {#cryptography}

Cryptography is also an indicator we need to consider when we design a proper solution. Choosing the right cryptographic algorithm is important. A checksum or CRC value is no longer considered to be strong protection. Cryptographic key management must be considered as part of a complete security solution.

**Previous Vulnerabilities:**

In [BlackHat 2007](https://www.blackhat.com/presentations/bh-usa-07/Heasman/Presentation/bh-usa-07-heasman.pdf), Heasman disclosed the PCI Option ROM rootkit, when UEFI secure boot is not avaiable yet.

In [BlackHat 2009](https://www.blackhat.com/presentations/bh-usa-09/CHEN/BHUSA09-Chen-RevAppleFirm-SLIDES.pdf), Chen demonstrated how to add a rootkit to Apple Keyboard firmware via a firmware update.

In [2010](https://media.ccc.de/v/27c3-4174-en-the_hidden_nemesis/related), Weinmann demonstrated how to add a rootkit to ThinkPad embedded controller (EC) firmware via update.

In [2011](https://academiccommons.columbia.edu/doi/10.7916/D8QJ7RG3), Cui demonstrated how to add a rootkit to HP printer firmware via update.

All of the cases above demonstrate the need for firmware locking and authenticated updates.

In [2010 27C3](https://academiccommons.columbia.edu/doi/10.7916/D8QJ7RG3), FailOverflow disclosed an issue in Sony Playstation 3 ECDSA code. The random number is NOT identical. As such the private key can be calculated.


```
def generate_ecdsa(k, sha):
  k = bytes_to_long(k)
  e = bytes_to_long(sha)
  m = open("/dev/random","rb").read(30) # Here call random function
  if len(m) != 30:
  raise Exception(“Failed to get m”)
  m = bytes_to_long(m) % ec_N
  r = (m * ec_G).x.tobignum() % ec_N
  kk = ((r * k) + e) % ec_N
  s = (bn_inv(m, ec_N) * kk) % ec_N
  r = long_to_bytes(r, 30)
  s = long_to_bytes(s, 30)
  return r,s
```

But the random function is implemented:

```
int getRandomNumber()
{
  return 4;
}
```

The random number must be generated in a cryptographically secure way. A hardware random number generator should be used if it is available.

In [ZeroNight 2018](https://airbus-seclab.github.io/ilo/ZERONIGHTS2018-Slides-EN-Turning_your_BMC_into_a_revolving_door-perigaud-gazet-czarny.pdf), researches disclosed broken logic in signature verification in BMC firmware.

See below code. load_legacy_key expects 1 as index for public key and fails otherwise. load_signature returns with success code if load_legacy_key failed for index2. Signatures felds are left untouched. As such, the attacker may update sig1 feld with hash value calculated and bypass the signature verification.


```
load_signature()
{
  steps_mask = 0;
  if ( load_legacy_key(hdr->index1 , &pkey , 0x804) )
  {
    steps_mask = 1;
    if ( decrypt_hash(hdr->sig1 , &sig_size , hdr->sig1 , sig_size , &pkey) )
      goto EXIT_FAILED;
  }
  if ( !load_legacy_key(hdr->index2 , &pkey , 0x804) )
    goto FUCK_YEAH; // <------ !!! NO FFS !!!
  steps = steps_mask | 2;

  if ( decrypt_hash(hdr->sig2 , &sig_size , hdr->sig2 , sig_size , &pkey) )
    goto EXIT_FAILED;

  if ( steps == 2 )
    memcpy(hdr->sig1 , sig2 , sig_size); // only sig2 , overwrite sig1

  // two sigs ? ensure they match
  if ( steps == 3 && memcmp(img_hdr_->sig1 , sig2 , sig_size) )
EXIT_FAILED:
    return ERROR;
FUCK_YEAH:
  return SUCCESS;
}
```


Care must be taken to make sure the signature verification always happening, espcially for the legacy logic.

