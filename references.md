<!--- @file
  references.md for EDK II Security Code Review Guide

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

# References {#references}

## Books and Papers {#books-and-papers}

[Cohen] _Best Kept Secrets of Peer Code Review_, [Jason Cohen](https://www.amazon.com/s/ref=dp_byline_sr_book_1?ie=UTF8&text=Jason+Cohen&search-alias=books&field-author=Jason+Cohen&sort=relevancerank), Smart Bear Inc., 2006, ISBN: 978-1599160672

[Freedman] _Handbook of Walkthroughs, Inspections, and Technical Reviews: Evaluating Programs, Projects, and Products,_ [Daniel P. Freedman](https://www.amazon.com/Daniel-P.-Freedman/e/B000APETK2/ref=dp_byline_cont_book_1) and [Gerald M. Weinberg](https://www.amazon.com/Gerald-M.-Weinberg/e/B000AP8TZ8/ref=dp_byline_cont_book_2), Dorset House, 1990, ISBN: 978-0932633194

[Gilb] _Software Inspection_, [Tom Gilb](https://www.amazon.com/s/ref=dp_byline_sr_book_1?ie=UTF8&text=Tom+Gilb&search-alias=books&field-author=Tom+Gilb&sort=relevancerank) and [Dorothy Graham](https://www.amazon.com/Dorothy-Graham/e/B005VWBCUO/ref=dp_byline_cont_book_2), Addison-Wesley Professional, 1994, ISBN: 978-0201631814

[Howard] Howard, M. (2006, July–August). “A Process for Performing Security Code Reviews.” IEEE Security &amp; Privacy, pp. 74–79, [https://www.researchgate.net/publication/3437819_A_process_for_performing_security_code_reviews?ev=auth_pub](https://www.researchgate.net/publication/3437819_A_process_for_performing_security_code_reviews?ev=auth_pub)

[Ransome] _Core Software Security: Security at the Source_, James Ransome and Anmol Misra, CRC Press, 2014, ISBN: 978-1466560956.

[Wiegers] _Peer Reviews in Software: A Practical Guide_, [Karl Wiegers](https://www.amazon.com/Karl-Wiegers/e/B001IGNXQS/ref=dp_byline_cont_book_1), Addison-Wesley Professional, 2001, ISBN: 978-0201734850

## Web {#web}

[CodeProject] Code review guidelines, https://www.codeproject.com/articles/524235/codeplusreviewplusguidelines

[Howard2] Howard, M. (2004, November). “Attack Surface: Mitigate Security Risks by Minimizing the Code You Expose to Untrusted Users.”, http://download.microsoft.com/download/3/a/7/3a7fa450-1f33-41f7-9e6d-3aa95b5a6aea/MSDNMagazineNovember2004en-us.chm

[Howard3] Howard, M. (2003, November). “Review It: Expert Tips for Finding Security Defects in Your Code”, [http://download.microsoft.com/download/3/a/7/3a7fa450-1f33-41f7-9e6d-3aa95b5a6aea/MSDNMagazineNovember2003en-us.chm](http://download.microsoft.com/download/3/a/7/3a7fa450-1f33-41f7-9e6d-3aa95b5a6aea/MSDNMagazineNovember2003en-us.chm)

[Meier] Meier, J., et al. (2005, October). “How To: Perform a Security Code Review for Managed Code (.NET Framework 2.0)”. https://docs.microsoft.com/en-us/previous-versions/msp-n-p/ff649315(v%3dpandp.10)

[OWASP] OWASP Code Review Guide, https://www.owasp.org/images/2/2e/OWASP_Code_Review_Guide-V1_1.pdf

#### Research &amp; Real World Examples {#research-real-world-examples}

[Wojtczuk BH 2009] Attack Intel BIOS,[https://www.blackhat.com/presentations/bh-usa-09/WOJTCZUK/BHUSA09-Wojtczuk-AtkIntelBios-SLIDES.pdf](https://www.blackhat.com/presentations/bh-usa-09/WOJTCZUK/BHUSA09-Wojtczuk-AtkIntelBios-SLIDES.pdf)

[Rutkowska BH DC 2009] Attack Intel TXT,[https://www.blackhat.com/presentations/bh-dc-09/Wojtczuk_Rutkowska/BlackHat-DC-09-Rutkowska-Attacking-Intel-TXT-slides.pdf](https://www.blackhat.com/presentations/bh-dc-09/Wojtczuk_Rutkowska/BlackHat-DC-09-Rutkowska-Attacking-Intel-TXT-slides.pdf)

[Bazhaniuk CSW 2015] A New Class of Vulnerability in SMI handlers, [http://www.c7zero.info/stuff/ANewClassOfVulnInSMIHandlers_csw2015.pdf](http://www.c7zero.info/stuff/ANewClassOfVulnInSMIHandlers_csw2015.pdf)

[ThinkPwn 2016] Exploring Lenovo,[http://blog.cr4.sh/2016/06/exploring-and-exploiting-lenovo.html](http://blog.cr4.sh/2016/06/exploring-and-exploiting-lenovo.html)

[Wojtczuk 2011] Attacking Intel TXT via SINIT Hijacking, https://invisiblethingslab.com/resources/2011/Attacking_Intel_TXT_via_SINIT_hijacking.pdf

[Kallenberg 2014] Extreme Privilege Escalation on Windows 8 UEFI System, [https://](https://www.mitre.org/sites/default/files/publications/14-2221-extreme-escalation-presentation.pdf)[www.mitre.org/sites/default/files/publications/14-2221-extreme-escalation-presentation.pdf](https://www.mitre.org/sites/default/files/publications/14-2221-extreme-escalation-presentation.pdf)

[Kallenberg CSW 2014] All your boot are belong to us, https://cansecwest.com/slides/2014/AllYourBoot_csw14-mitre-final.pdf

[Wojtczuk CSW 2015] Attacks on UEFI Security, [https://cansecwest.com/slides/2015/AttacksOnUEFI_Rafal.pptx](https://cansecwest.com/slides/2015/AttacksOnUEFI_Rafal.pptx)

[Evdokimov BH 2017] Intel AMT Stealth Breakthrough,[https://](https://www.blackhat.com/docs/us-17/thursday/us-17-Evdokimov-Intel-AMT-Stealth-Breakthrough.pdf)[www.blackhat.com/docs/us-17/thursday/us-17-Evdokimov-Intel-AMT-Stealth-Breakthrough.pdf](https://www.blackhat.com/docs/us-17/thursday/us-17-Evdokimov-Intel-AMT-Stealth-Breakthrough.pdf)

[Perigaud SSTIC 2018] Backdooring your server through its BMC,[https://www.sstic.org/media/SSTIC2018/SSTIC-actes/subverting_your_server_through_its_bmc_the_hpe_ilo/SSTIC2018-Slides-subverting_your_server_through_its_bmc_the_hpe_ilo4_case-gazet_perigaud_czarny.pdf](https://www.sstic.org/media/SSTIC2018/SSTIC-actes/subverting_your_server_through_its_bmc_the_hpe_ilo/SSTIC2018-Slides-subverting_your_server_through_its_bmc_the_hpe_ilo4_case-gazet_perigaud_czarny.pdf)

[Waisman BH 2018] The Unbearable Lightness of BMCs,[http://i.blackhat.com/us-18/Wed-August-8/us-18-Waisman-Soler-The-Unbearable-Lightness-of-BMC.pdf](http://i.blackhat.com/us-18/Wed-August-8/us-18-Waisman-Soler-The-Unbearable-Lightness-of-BMC.pdf)

[Matrosov BH 2019 2] Breaking Through Another Side, [http://i.blackhat.com/USA-19/Thursday/us-19-Matrosov-Breaking-Through-Another-Side-Bypassing-Firmware-Security-Boundaries-From-Embedded-Controller.pdf](http://i.blackhat.com/USA-19/Thursday/us-19-Matrosov-Breaking-Through-Another-Side-Bypassing-Firmware-Security-Boundaries-From-Embedded-Controller.pdf)

[SpeedRacer 2014] Speed Racer, [https://fahrplan.events.ccc.de/congress/2014/Fahrplan/system/attachments/2565/original/speed_racer_whitepaper.pdf](https://fahrplan.events.ccc.de/congress/2014/Fahrplan/system/attachments/2565/original/speed_racer_whitepaper.pdf)

[Rutkowska BH 2008] Preventing and Detecting Xen Hypervisor Subversions, [https://](https://invisiblethingslab.com/resources/bh08/part2-full.pdf)[invisiblethingslab.com/resources/bh08/part2-full.pdf](https://invisiblethingslab.com/resources/bh08/part2-full.pdf)

[Tereshkin BH 2009] A Ring -3 Rootkits,[https://](https://invisiblethingslab.com/resources/bh09usa/Ring%20-3%20Rootkits.pdf)[invisiblethingslab.com/resources/bh09usa/Ring%20-3%20Rootkits.pdf](https://invisiblethingslab.com/resources/bh09usa/Ring%20-3%20Rootkits.pdf)

[Bulygin RC 2017] Baring the system, http[://](http://www.c7zero.info/stuff/REConBrussels2017_BARing_the_system.pdf)[www.c7zero.info/stuff/REConBrussels2017_BARing_the_system.pdf](http://www.c7zero.info/stuff/REConBrussels2017_BARing_the_system.pdf)

[Wojtczuk 2009] Another TXT Attack, [https://invisiblethingslab.com/resources/misc09/Another%20TXT%20Attack.pdf](https://invisiblethingslab.com/resources/misc09/Another%20TXT%20Attack.pdf)

[Duflot CSW 2009] SMM Reloaded,[https://](https://cansecwest.com/csw09/csw09-duflot.pdf)[cansecwest.com/csw09/csw09-duflot.pdf](https://cansecwest.com/csw09/csw09-duflot.pdf)

[Sevinsky BH 2013] Funderbolt – Adventures in thunderbolt DMA attacks,[https://media.blackhat.com/us-13/US-13-Sevinsky-Funderbolt-Adventures-in-Thunderbolt-DMA-Attacks-Slides.pdf](https://media.blackhat.com/us-13/US-13-Sevinsky-Funderbolt-Adventures-in-Thunderbolt-DMA-Attacks-Slides.pdf)

[Hudson 31c3 2015] Thunderstrike, [https://trmm.net/Thunderstrike_31c3](https://trmm.net/Thunderstrike_31c3)

[Hudson BH 2015] Thunderstrike 2, [https://www.blackhat.com/docs/us-15/materials/us-15-Hudson-Thunderstrike-2-Sith-Strike.pdf](https://www.blackhat.com/docs/us-15/materials/us-15-Hudson-Thunderstrike-2-Sith-Strike.pdf)

[Pcileech 2017] Attacking UEFI and Linux, [http://blog.frizk.net/2017/01/attacking-uefi-and-linux.html](http://blog.frizk.net/2017/01/attacking-uefi-and-linux.html)

[Chavez-Corona CSW 2017] Abusing CPU Hot-Add weaknesses to escalate privileges in Server Datacenters, [https://cansecwest.com/slides/2017/CSW2017_Cuauhtemoc-Rene_CPU_Hot-Add_flow.pdf](https://cansecwest.com/slides/2017/CSW2017_Cuauhtemoc-Rene_CPU_Hot-Add_flow.pdf)

[Facedancer 2012] Facedancer, [http://goodfet.sourceforge.net/hardware/facedancer21/](http://goodfet.sourceforge.net/hardware/facedancer21/)

[Schumilo BH 2014] Don’t trust your USB,[https://](https://www.blackhat.com/docs/eu-14/materials/eu-14-Schumilo-Dont-Trust-Your-USB-How-To-Find-Bugs-In-USB-Device-Drivers.pdf)[www.blackhat.com/docs/eu-14/materials/eu-14-Schumilo-Dont-Trust-Your-USB-How-To-Find-Bugs-In-USB-Device-Drivers.pdf](https://www.blackhat.com/docs/eu-14/materials/eu-14-Schumilo-Dont-Trust-Your-USB-How-To-Find-Bugs-In-USB-Device-Drivers.pdf)

[Boone CSW 2018] TPM Genie, [https://github.com/nccgroup/TPMGenie/blob/master/docs/CanSecWest_2018_-_TPM_Genie_-_](https://github.com/nccgroup/TPMGenie/blob/master/docs/CanSecWest_2018_-_TPM_Genie_-_Jeremy_Boone.pdf)[Jeremy_Boone.pdf](https://github.com/nccgroup/TPMGenie/blob/master/docs/CanSecWest_2018_-_TPM_Genie_-_Jeremy_Boone.pdf)

[Brossard DC 2008] Bypassing Pre-boot Authentication Passwords, [https://](https://www.defcon.org/images/defcon-16/dc16-presentations/brossard/defcon-16-brossard-wp.pdf)[www.defcon.org/images/defcon-16/dc16-presentations/brossard/defcon-16-brossard-wp.pdf](https://www.defcon.org/images/defcon-16/dc16-presentations/brossard/defcon-16-brossard-wp.pdf)

[Miller BH 2011] Battery Firmware Hacking, [https://media.blackhat.com/bh-us-11/Miller/BH_US_11_Miller_Battery_Firmware_Public_Slides.pdf](https://media.blackhat.com/bh-us-11/Miller/BH_US_11_Miller_Battery_Firmware_Public_Slides.pdf)

[Duflot 2006] Using CPU System Management Mode to Circumvent Operating System Security Function, [https://www.researchgate.net/publication/241643659_Using_CPU_System_Management_Mode_to_Circumvent_Operating_System_Security_Functions](https://www.researchgate.net/publication/241643659_Using_CPU_System_Management_Mode_to_Circumvent_Operating_System_Security_Functions)

[CIH 1998] CIH, [https://en.wikipedia.org/wiki/CIH_(computer_virus)](https://en.wikipedia.org/wiki/CIH_(computer_virus))

[Sun 2007] BIOS Boot Hijacking, [http://powerofcommunity.net/poc2007/sunbing.pdf](http://powerofcommunity.net/poc2007/sunbing.pdf)

[Ermolov 2016] Safeguarding Rootkits: Intel Boot Guard, [https://github.com/flothrone/bootguard/blob/master/Intel%20BootGuard%20final.pdf](https://github.com/flothrone/bootguard/blob/master/Intel%20BootGuard%20final.pdf)

[Ermolov DC 2017] Safeguarding Rootkits: Intel Boot Guard (part2),[https://github.com/flothrone/bootguard/blob/master/Intel%20BG%20part2.pdf](https://github.com/flothrone/bootguard/blob/master/Intel%20BG%20part2.pdf)

[Matrosov BH 2017] Betraying the BIOS, [https://](https://www.blackhat.com/docs/us-17/wednesday/us-17-Matrosov-Betraying-The-BIOS-Where-The-Guardians-Of-The-BIOS-Are-Failing.pdf)[www.blackhat.com/docs/us-17/wednesday/us-17-Matrosov-Betraying-The-BIOS-Where-The-Guardians-Of-The-BIOS-Are-Failing.pdf](https://www.blackhat.com/docs/us-17/wednesday/us-17-Matrosov-Betraying-The-BIOS-Where-The-Guardians-Of-The-BIOS-Are-Failing.pdf)

[Matrosov BH 2019] Modern Secure Boot Attacks,[http://i.blackhat.com/asia-19/Fri-March-29/bh-asia-Matrosov-Modern-Secure-Boot-Attacks.pdf](http://i.blackhat.com/asia-19/Fri-March-29/bh-asia-Matrosov-Modern-Secure-Boot-Attacks.pdf)

[Han BH 2018] I don’t want to sleep tonight – Subverting Intel TXT with S3 Sleep, [https://i.blackhat.com/briefings/asia/2018/asia-18-Seunghun-I_Dont_Want_to_Sleep_Tonight_Subverting_Intel_TXT_with_S3_Sleep.pdf](https://i.blackhat.com/briefings/asia/2018/asia-18-Seunghun-I_Dont_Want_to_Sleep_Tonight_Subverting_Intel_TXT_with_S3_Sleep.pdf)

[Han BH 2019] Finally I can sleep tonight – catching sleep mode vulnerabilities of the TPM with the napper, [http](http://i.blackhat.com/asia-19/Thu-March-28/bh-asia-Seunghun-Finally-I-Can-Sleep-Tonight-Catching-Sleep-Mode-Vulnerabilities-of-the-TPM-with-the-Napper.pdf)[://](http://i.blackhat.com/asia-19/Thu-March-28/bh-asia-Seunghun-Finally-I-Can-Sleep-Tonight-Catching-Sleep-Mode-Vulnerabilities-of-the-TPM-with-the-Napper.pdf)[i.blackhat.com/asia-19/Thu-March-28/bh-asia-Seunghun-Finally-I-Can-Sleep-Tonight-Catching-Sleep-Mode-Vulnerabilities-of-the-TPM-with-the-Napper.pdf](http://i.blackhat.com/asia-19/Thu-March-28/bh-asia-Seunghun-Finally-I-Can-Sleep-Tonight-Catching-Sleep-Mode-Vulnerabilities-of-the-TPM-with-the-Napper.pdf)

[Heasman BH 2007] Hacking the Extensible Firmware Interface, [https://www.blackhat.com/presentations/bh-usa-07/Heasman/Presentation/bh-usa-07-heasman.pdf](https://www.blackhat.com/presentations/bh-usa-07/Heasman/Presentation/bh-usa-07-heasman.pdf)

[Chen BH 2009] Reversing and exploiting an Apple firmware update, [https://](https://www.blackhat.com/presentations/bh-usa-09/CHEN/BHUSA09-Chen-RevAppleFirm-SLIDES.pdf)[www.blackhat.com/presentations/bh-usa-09/CHEN/BHUSA09-Chen-RevAppleFirm-SLIDES.pdf](https://www.blackhat.com/presentations/bh-usa-09/CHEN/BHUSA09-Chen-RevAppleFirm-SLIDES.pdf)

[Weinmann 2010] The hidden nemesis,[https://media.ccc.de/v/27c3-4174-en-the_hidden_nemesis/related](https://media.ccc.de/v/27c3-4174-en-the_hidden_nemesis/related)

[Cui BH 2011] Print me if you dare,[https://academiccommons.columbia.edu/doi/10.7916/D8QJ7RG3](https://academiccommons.columbia.edu/doi/10.7916/D8QJ7RG3)

[Perigaud ZeroNight 2018] Turning your BMC into a revolving door,[https://airbus-seclab.github.io/ilo/ZERONIGHTS2018-Slides-EN-Turning_your_BMC_into_a_revolving_door-perigaud-gazet-czarny.pdf](https://airbus-seclab.github.io/ilo/ZERONIGHTS2018-Slides-EN-Turning_your_BMC_into_a_revolving_door-perigaud-gazet-czarny.pdf)

[Domas BH 2018] God Mode Unlocked Hardware Backdoors in X86 CPUs, http://i.blackhat.com/us-18/Thu-August-9/us-18-Domas-God-Mode-Unlocked-Hardware-Backdoors-In-x86-CPUs.pdf

Authors

**Jiewen Yao** (jiewen.yao@intel.com) is a Principal Engineer with Intel Architecture, Graphic and Software Group at Intel Corporation. He is security architect in EDK II BIOS. Jiewen is member of UEFI Security Sub-team and PI Security Sub-team in the UEFI Forum.

**Chris Wu** (chris.wu@intel.com) is a validation leader with Intel Architecture, Graphic and Software Group at Intel Corporation.

**Vincent J. Zimmer** (vincent.zimmer@intel.com) is a Senior Principal Engineer with Intel Architecture, Graphic and Software Group at Intel Corporation. Vincent chairs the UEFI Security and Network Sub-teams in the UEFI Forum.