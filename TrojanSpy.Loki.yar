rule spy_loki {
   meta:
      description = "TrojanSpy.Loki"
      author = "LightDefender"
      date = "2021-06-13"
      hash1 = "10a7285287f351ae201ec72dea640fd1eabf1a7c54955f9fbd6de4e4a5309642"
   strings:
      $s1 = "sheFDll32.dll" fullword ascii
      $s2 = "flfjaseriernechasmykaramboleren.exe" fullword wide
      $s3 = "\\MSINFO32.EXE" fullword wide
      $s4 = "PZwSetInformationProcess" fullword ascii
      $s5 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s6 = "overhardnessekstrabevillingernesti" fullword ascii
      $s7 = "The temp. path is " fullword wide
      $s8 = "FDkernel32" fullword ascii
      $s9 = "CERTERT.kpd" fullword wide
      $s10 = "dullestmisseemgruesomelysubdivida" fullword ascii
      $s11 = "historiometrykontooverfrslerdisrup" fullword ascii
      $s12 = "departementerstwatsevolvementsaar" fullword ascii
      $s13 = "topfartsmedellinpyrolaceaebedrive" fullword ascii
      $s14 = "jerezlssetsfantasiestaabeligeobje" fullword ascii
      $s15 = "facetslebetantipatrioticdasjohn" fullword ascii
      $s16 = "regionarybookkeepslystendesumme" fullword ascii
      $s17 = "delsindballelssernesocialraadgive" fullword ascii
      $s18 = "biciliatemockspersimmonevenmetefl" fullword ascii
      $s19 = "nomarchyhermelinsskindetsspidsbel" fullword ascii
      $s20 = "aaenchitinogenoushrgulesidevaegge" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      5 of them
}
rule STEALER_Lokibot
 {
   meta:

      description = "Rule to detect Lokibot stealer"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2020-09-23"
      rule_version = "v1"
      malware_type = "stealer"
      malware_family = "Ransomware:W32/Lokibot"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash1 = "0e40f4fdd77e1f90279c585cfc787942b8474e5216ff4d324d952ef6b74f25d2"
      hash2 = "3ad36afad12d8cf245904285c21a8db43f9ed9c82304fdc2f27c4dd1438e4a1d"
      hash3 = "26fbdd516b3c1bfa36784ef35d6bc216baeb0ef2d0c0ba036ff9296da2ce2c84"

    strings:

        $sq1 = { 55 8B EC 56 8B 75 08 57 56 E8 ?? ?? ?? ?? 8B F8 59 85 FF 75 04 33 C0 EB 20 56 6A 00 57 E8 ?? ?? ?? ?? 6A 0C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 E5 83 60 08 00 89 38 89 70 04 5F 5E 5D C3 }
        $sq2 = { 55 8B EC 83 EC 0C 53 56 57 33 DB BE ?? ?? ?? ?? 53 53 56 6A 09 E8 ?? ?? ?? ?? 6A 10 6A 01 53 53 8D 4D F8 51 FF D0 53 53 56 6A 09 E8 ?? ?? ?? ?? 6A 08 6A 01 53 53 8D 4D F8 51 FF D0 85 C0 0F 84 2B 01 00 00 6A 24 E8 ?? ?? ?? ?? 59 8B D8 33 C0 6A 09 59 8B FB F3 AB 66 8B 4D 24 B8 03 66 00 00 C7 03 08 02 00 00 66 85 C9 74 03 0F B7 C1 8B 4D 08 33 D2 0F B7 C0 89 43 04 89 53 08 85 C9 74 12 C7 43 08 08 00 00 00 8B 01 89 43 0C 8B 41 04 89 43 10 8B 4D 0C 85 C9 74 0F 83 43 08 08 8B 01 89 43 14 8B 41 04 89 43 18 8B 4D 10 85 C9 74 0F 83 43 08 08 8B 01 89 43 1C 8B 41 04 89 43 20 8B 7B 08 8B 75 F8 83 C7 0C 52 52 68 ?? ?? ?? ?? 6A 09 E8 ?? ?? ?? ?? 8D 4D FC 51 6A 00 6A 00 57 53 56 FF D0 85 C0 74 75 8B 75 FC 33 C0 40 83 7D 20 00 0F 45 45 20 33 FF 57 57 68 ?? ?? ?? ?? 6A 09 89 45 F4 E8 ?? ?? ?? ?? 57 8D 4D F4 51 6A 04 56 FF D0 85 C0 74 3B 39 7D 14 74 1A 8B 75 FC 57 57 68 ?? ?? ?? ?? 6A 09 E8 ?? ?? ?? ?? 57 FF 75 14 6A 01 56 FF D0 8B 55 18 8B 4D FC 53 89 0A 8B 55 1C 8B 4D F8 89 0A E8 ?? ?? ?? ?? 33 C0 59 40 EB 21 FF 75 FC E8 BF FB FF FF 59 EB 02 33 FF 53 E8 ?? ?? ?? ?? 57 FF 75 F8 E8 6B FB FF FF 83 C4 0C 33 C0 5F 5E 5B 8B E5 5D C3 }
        $sq3 = { 55 8B EC 83 EC 0C 53 8B 5D 0C 56 57 6A 10 33 F6 89 75 F8 89 75 FC 58 89 45 F4 85 DB 75 0E FF 75 08 E8 ?? ?? ?? ?? 8B D8 8B 45 F4 59 50 E8 ?? ?? ?? ?? 8B F8 59 85 FF 0F 84 B6 00 00 00 FF 75 F4 56 57 E8 C4 ?? ?? ?? 83 C4 0C 56 56 68 ?? ?? ?? ?? 6A 09 E8 ?? ?? ?? ?? 68 00 00 00 F0 6A 01 56 56 8D 4D F8 51 FF D0 85 C0 0F 84 84 00 00 00 8B 75 F8 6A 00 6A 00 68 ?? ?? ?? ?? 6A 09 E8 ?? ?? ?? ?? 8D 4D FC 51 6A 00 6A 00 68 03 80 00 00 56 FF D0 85 C0 74 51 6A 00 53 FF 75 08 FF 75 FC E8 7F FD FF FF 83 C4 10 85 C0 74 3C 8B 75 FC 6A 00 6A 00 68 ?? ?? ?? ?? 6A 09 E8 ?? ?? ?? ?? 6A 00 8D 4D F4 51 57 6A 02 56 FF D0 85 C0 74 19 FF 75 FC E8 16 FD FF FF 6A 00 FF 75 F8 E8 26 FD FF FF 83 C4 0C 8B C7 EB 0E 6A 00 FF 75 F8 E8 15 FD FF FF 59 59 33 C0 5F 5E 5B 8B E5 5D C3 }
        $sq4 = { 55 8B EC 83 7D 10 00 56 57 8B 7D 0C 57 74 0E E8 ?? ?? ?? ?? 8B F0 33 C0 03 F6 40 EB 09 E8 ?? ?? ?? ?? 8B F0 33 C0 83 7D 14 00 59 75 24 50 FF 75 08 E8 2C 00 00 00 59 59 83 F8 01 74 04 33 C0 EB 1D 56 FF 75 08 E8 C5 FE FF FF 59 59 83 F8 01 75 EC 56 57 FF 75 08 E8 CA FE FF FF 83 C4 0C 5F 5E 5D C3 }
        $sq5 = { 55 8B EC 53 56 8B 75 0C 57 85 F6 75 0B FF 75 08 E8 ?? ?? ?? ?? 59 8B F0 6B C6 03 89 45 0C 8D 58 01 53 E8 ?? ?? ?? ?? 8B F8 59 85 FF 74 42 53 6A 00 57 E8 ?? ?? ?? ?? 83 C4 0C 33 D2 85 F6 74 27 8B 45 08 0F B6 0C 02 8B C1 83 E1 0F C1 E8 04 8A 80 ?? ?? ?? ?? 88 04 57 8A 81 ?? ?? ?? ?? 88 44 57 01 42 3B D6 72 D9 8B 45 0C C6 04 07 00 8B C7 5F 5E 5B 5D C3 }
        $sq6 = { 55 8B EC 53 56 57 FF 75 08 E8 ?? ?? ?? ?? 33 C9 6A 02 5B 8D B8 A0 1F 00 00 8B C7 F7 E3 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 8B F0 59 59 85 F6 74 6F 8D 0C 3F 51 6A 00 56 E8 ?? ?? ?? ?? 8D 45 0C 50 FF 75 08 56 E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 8B F8 83 C4 1C 85 FF 74 40 33 C9 8D 47 02 F7 E3 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 8B D8 59 85 DB 74 25 8D 0C 7D 02 00 00 00 51 6A 00 53 E8 ?? ?? ?? ?? 57 56 53 E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 1C 8B C3 EB 09 56 E8 ?? ?? ?? ?? 59 33 C0 5F 5E 5B 5D C3 }
        $sq7 = { 55 8B EC 81 EC 80 00 00 00 56 57 E8 ?? ?? ?? ?? 6A 1F 59 BE ?? ?? ?? ?? 8D 7D 80 F3 A5 33 C9 6A 02 5A 66 A5 8B 7D 08 8D 47 01 F7 E2 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 8B F0 59 85 F6 74 4D 8D 04 7D 02 00 00 00 4F 89 45 08 53 50 6A 00 56 E8 ?? ?? ?? ?? 83 C4 0C 33 DB 85 FF 74 1C E8 ?? ?? ?? ?? 33 D2 6A 7E 59 F7 F1 D1 EA 66 8B 44 55 80 66 89 04 5E 43 3B DF 72 E4 56 E8 ?? ?? ?? ?? 3B F8 8B 45 08 59 77 C4 8B C6 5B EB 02 33 C0 5F 5E 8B E5 5D C3 }
        $sq8 = { 55 8B EC 81 EC 50 02 00 00 53 56 57 6A 0A E8 ?? ?? ?? ?? 59 33 DB 6A 2E 5E 39 5D 14 0F 84 13 01 00 00 FF 75 08 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 59 59 85 F6 0F 84 F7 00 00 00 53 53 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8D 8D B0 FD FF FF 51 56 FF D0 8B D8 83 FB FF 0F 84 CC 00 00 00 F6 85 B0 FD FF FF 10 0F 84 97 00 00 00 83 7D 1C 00 74 2E 8D 85 DC FD FF FF 68 ?? ?? ?? ?? 50 E8 0A ?? ?? ?? 59 59 85 C0 75 7A 8D 85 DC FD FF FF 68 ?? ?? ?? ?? 50 E8 F3 ?? ?? ?? 59 59 85 C0 75 63 8D 85 DC FD FF FF 50 E8 ?? ?? ?? ?? 59 83 F8 03 73 0C 6A 2E 58 66 39 85 DC FD FF FF 74 45 8D 85 DC FD FF FF 50 FF 75 08 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 89 45 14 85 C0 74 27 6A 01 6A 00 6A 01 FF 75 10 FF 75 0C 50 E8 14 FF FF FF FF 75 14 8B F8 E8 ?? ?? ?? ?? 83 C4 1C 85 FF 0F 85 EE 00 00 00 33 C0 50 50 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 8D B0 FD FF FF 51 53 FF D0 85 C0 0F 85 3B FF FF FF 53 E8 ?? ?? ?? ?? 59 56 E8 ?? ?? ?? ?? 59 33 DB 6A 2E 5E FF 75 0C FF 75 08 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F8 83 C4 0C 85 FF 0F 84 CF 00 00 00 53 53 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8D 8D B0 FD FF FF 51 57 FF D0 8B D8 83 FB FF 0F 84 A6 00 00 00 8D 85 DC FD FF FF 50 E8 ?? ?? ?? ?? 59 83 F8 03 73 09 66 39 B5 DC FD FF FF 74 3E 83 BD B0 FD FF FF 10 75 06 83 7D 18 00 74 2F 8D 85 DC FD FF FF 50 FF 75 08 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 83 C4 0C 85 F6 74 12 83 7D 10 00 74 40 56 FF 55 10 56 E8 ?? ?? ?? ?? 59 59 33 C0 50 50 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 8D B0 FD FF FF 51 53 FF D0 85 C0 74 29 6A 2E 5E EB 85 56 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 59 59 8B C7 EB 22 57 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 59 59 8B C6 EB 10 53 E8 ?? ?? ?? ?? 59 57 E8 ?? ?? ?? ?? 59 33 C0 5F 5E 5B 8B E5 5D C3 }
        $sq9 = { 83 3D 14 ?? ?? ?? ?? 56 74 0A 8B 35 20 ?? ?? ?? 85 F6 75 66 53 57 BB E0 01 00 00 33 FF 53 89 3D 14 ?? ?? ?? E8 F0 F8 FF FF 33 F6 A3 14 ?? ?? ?? 46 59 85 C0 74 12 6A 78 57 50 89 35 20 ?? ?? ?? E8 A6 F8 FF FF 83 C4 0C 53 89 3D 18 ?? ?? ?? E8 C5 F8 FF FF A3 18 ?? ?? ?? 59 85 C0 74 14 6A 78 57 50 89 35 20 ?? ?? ?? E8 7E F8 FF FF 83 C4 0C EB 06 8B 35 20 ?? ?? ?? 5F 5B 8B C6 5E C3 }
        $sq10 = { 55 8B EC 51 51 83 65 FC 00 53 56 57 64 A1 30 00 00 00 89 45 FC 8B 45 FC 8B 40 0C 8B 58 0C 8B F3 8B 46 18 FF 76 28 89 45 F8 E8 CE FA FF FF 8B F8 59 85 FF 74 1F 6A 00 57 E8 32 01 00 00 57 E8 ?? ?? ?? ?? 03 C0 50 57 E8 71 FA FF FF 83 C4 14 39 45 08 74 11 8B 36 3B DE 75 C6 33 C0 5F 5E 5B 8B E5 5D C2 04 00 8B 45 F8 EB F2 }
        $sq11 = { A1 ?? ?? ?? ?? 85 C0 74 07 50 E8 ?? ?? ?? ?? 59 A1 ?? ?? ?? ?? 85 C0 74 07 50 E8 ?? ?? ?? ?? 59 A1 ?? ?? ?? ?? 85 C0 74 07 50 E8 ?? ?? ?? ?? 59 33 C0 A3 ?? ?? ?? ?? A3 ?? ?? ?? ?? A3 ?? ?? ?? ?? C3 }
        $sq12 = { 55 8B EC 56 8B 75 0C 57 85 F6 74 48 56 E8 ?? ?? ?? ?? 59 85 C0 74 3D 56 E8 ?? ?? ?? ?? 59 85 C0 74 32 83 65 0C 00 8D 45 0C 6A 01 50 56 E8 ?? ?? ?? ?? 8B F8 83 C4 0C 85 FF 74 19 8B 45 0C 85 C0 74 12 83 7D 14 00 74 12 39 45 14 73 0D 57 E8 ?? ?? ?? ?? 59 33 C0 5F 5E 5D C3 83 7D 10 00 74 1A 6A 00 6A 01 56 E8 ?? ?? ?? ?? 59 50 FF 75 08 E8 1F 00 00 00 8B 45 0C 83 C4 10 50 57 FF 75 08 E8 FF FE FF FF 57 8B F0 E8 ?? ?? ?? ?? 83 C4 10 8B C6 EB C3 }
        $sq13 = { 55 8B EC 83 EC 18 56 FF 75 08 E8 ?? ?? ?? ?? 50 89 45 F0 E8 ?? ?? ?? ?? 8B F0 59 59 85 F6 0F 84 C0 00 00 00 53 8B 5D 0C 33 C9 57 6A 04 5A 8B C3 F7 E2 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 83 65 F4 00 8B F8 83 65 FC 00 59 85 DB 74 6D 8B 45 10 83 C0 FC FF 75 F0 83 C0 04 89 45 E8 6A 00 56 8B 00 89 45 EC E8 ?? ?? ?? ?? FF 75 F0 FF 75 08 56 E8 ?? ?? ?? ?? 83 65 F8 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 20 EB 1F FF 75 EC 50 E8 ?? ?? ?? ?? 59 59 85 C0 75 32 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? FF 45 F8 59 59 85 C0 75 DD 8B 45 FC 40 89 45 FC 3B C3 8B 45 E8 72 99 56 E8 ?? ?? ?? ?? 59 39 5D F4 75 12 8B C7 EB 17 8B 45 FC 8B 4D F8 FF 45 F4 89 0C 87 EB D7 57 E8 ?? ?? ?? ?? 59 33 C0 5F 5B 5E 8B E5 5D C3 }
        $sq14 = { 55 8B EC 8B 45 0C 53 56 8B 75 08 57 8B 4E 04 03 C1 8D 3C 09 3B F8 77 06 8D B8 F4 01 00 00 33 C9 8B C7 6A 04 5A F7 E2 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 8B D8 59 85 DB 74 26 57 6A 00 53 E8 ?? ?? ?? ?? FF 76 08 FF 36 53 E8 ?? ?? ?? ?? FF 36 E8 ?? ?? ?? ?? 33 C0 89 1E 83 C4 1C 89 7E 04 40 5F 5E 5B 5D C3 }
        $sq15 = { 55 8B EC 83 7D 0C 00 57 74 39 8B 7D 10 85 FF 74 32 56 8B 75 08 8B 46 08 03 C7 3B 46 04 76 09 57 56 E8 3F FF FF FF 59 59 8B 46 08 03 06 57 FF 75 0C 50 E8 ?? ?? ?? ?? 01 7E 08 83 C4 0C 33 C0 40 5E EB 02 33 C0 5F 5D C3 }

    condition:

       uint16(0) == 0x5a4d and
       any of them 
}

rule win_lokipws_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-12-22"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lokipws"
        malpedia_rule_date = "20201222"
        malpedia_hash = "30354d830a29f0fbd3714d93d94dea941d77a130"
        malpedia_version = "20201023"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 6a00 6a00 99 52 50 6a02 57 }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   99                   | cdq                 
            //   52                   | push                edx
            //   50                   | push                eax
            //   6a02                 | push                2
            //   57                   | push                edi

        $sequence_1 = { 56 e8???????? 53 53 ff35???????? e8???????? ff35???????? }
            // n = 7, score = 200
            //   56                   | push                esi
            //   e8????????           |                     
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   ff35????????         |                     
            //   e8????????           |                     
            //   ff35????????         |                     

        $sequence_2 = { 8b450c 85c0 7402 8938 56 56 68e2d4ead4 }
            // n = 7, score = 200
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   85c0                 | test                eax, eax
            //   7402                 | je                  4
            //   8938                 | mov                 dword ptr [eax], edi
            //   56                   | push                esi
            //   56                   | push                esi
            //   68e2d4ead4           | push                0xd4ead4e2

        $sequence_3 = { 53 8b5d14 56 57 8b7d0c 3b38 7543 }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   8b5d14               | mov                 ebx, dword ptr [ebp + 0x14]
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b7d0c               | mov                 edi, dword ptr [ebp + 0xc]
            //   3b38                 | cmp                 edi, dword ptr [eax]
            //   7543                 | jne                 0x45

        $sequence_4 = { e8???????? 8bd8 83c40c 85db 7411 6a02 53 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   83c40c               | add                 esp, 0xc
            //   85db                 | test                ebx, ebx
            //   7411                 | je                  0x13
            //   6a02                 | push                2
            //   53                   | push                ebx

        $sequence_5 = { 6a64 5e 6a5c 668945d0 58 6a4e 668945d6 }
            // n = 7, score = 200
            //   6a64                 | push                0x64
            //   5e                   | pop                 esi
            //   6a5c                 | push                0x5c
            //   668945d0             | mov                 word ptr [ebp - 0x30], ax
            //   58                   | pop                 eax
            //   6a4e                 | push                0x4e
            //   668945d6             | mov                 word ptr [ebp - 0x2a], ax

        $sequence_6 = { 59 33c0 50 50 68cc7744ce 50 }
            // n = 6, score = 200
            //   59                   | pop                 ecx
            //   33c0                 | xor                 eax, eax
            //   50                   | push                eax
            //   50                   | push                eax
            //   68cc7744ce           | push                0xce4477cc
            //   50                   | push                eax

        $sequence_7 = { 50 57 50 e8???????? 68???????? 8d8b04020000 }
            // n = 6, score = 200
            //   50                   | push                eax
            //   57                   | push                edi
            //   50                   | push                eax
            //   e8????????           |                     
            //   68????????           |                     
            //   8d8b04020000         | lea                 ecx, [ebx + 0x204]

        $sequence_8 = { 8bf0 e8???????? 83c42c 85f6 746f 68???????? }
            // n = 6, score = 200
            //   8bf0                 | mov                 esi, eax
            //   e8????????           |                     
            //   83c42c               | add                 esp, 0x2c
            //   85f6                 | test                esi, esi
            //   746f                 | je                  0x71
            //   68????????           |                     

        $sequence_9 = { 8945fc 8d45ac 68???????? 50 e8???????? 83c424 8945f8 }
            // n = 7, score = 200
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8d45ac               | lea                 eax, [ebp - 0x54]
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c424               | add                 esp, 0x24
            //   8945f8               | mov                 dword ptr [ebp - 8], eax

    condition:
        7 of them and filesize < 1327104
}
