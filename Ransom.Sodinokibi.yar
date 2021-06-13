rule Sodinokibi_Loader{

    meta:
        description = "Sodinokibi/REvil signature (Loader)"
        author = "@Pro_Integritate"
        maltype = "Ransomware"

    strings:
        $string1 = "function Invoke-" nocase
        $string2 = "$ForceASLR" nocase
        $string3 = "$DoNotZeroMZ" nocase
        $string4 = "$RemoteScriptBlock" nocase
        $string5 = "$TypeBuilder" nocase
        $string6 = "$Win32Constants" nocase
        $string7 = "$OpenProcess" nocase
        $string8 = "$WaitForSingleObject" nocase
        $string9 = "$WriteProcessMemory" nocase
        $string10 = "$ReadProcessMemory" nocase
        $string11 = "$CreateRemoteThread" nocase
        $string12 = "$OpenThreadToken" nocase
        $string13 = "$AdjustTokenPrivileges" nocase
        $string14 = "$LookupPrivilegeValue" nocase
        $string15 = "$ImpersonateSelf" nocase
        $string16 = "-SignedIntAsUnsigned" nocase
        $string17 = "Get-Win32Types" nocase
        $string18 = "Get-Win32Functions" nocase
        $string19 = "Write-BytesToMemory" nocase
        $string20 = "Get-ProcAddress" nocase
        $string21 = "Enable-SeDebugPrivilege" nocase
        $string22 = "Get-ImageNtHeaders" nocase
        $string23 = "Get-PEBasicInfo" nocase
        $string24 = "Get-PEDetailedInfo" nocase
        $string25 = "Import-DllInRemoteProcess" nocase
        $string26 = "Get-RemoteProcAddress" nocase
        $string27 = "Update-MemoryAddresses" nocase
        $string28 = "Import-DllImports" nocase
        $string29 = "Get-VirtualProtectValue" nocase
        $string30 = "Update-MemoryProtectionFlags" nocase
        $string31 = "Update-ExeFunctions" nocase
        $string32 = "Copy-ArrayOfMemAddresses" nocase
        $string33 = "Get-MemoryProcAddress" nocase
        $string34 = "Invoke-MemoryLoadLibrary" nocase
        $string35 = "Invoke-MemoryFreeLibrary" nocase
        $string36 = "$PEBytes32" nocase
        $string37 = "TVqQAA"
        $string38 = "FromBase64String" nocase

    condition:
	uint16(0) == 0x5a4d and 30 of ($string*)

}

import "pe"

rule ransomware_sodinokibi {
   meta:
      description = "Using a recently disclosed vulnerability in Oracle WebLogic, criminals use it to install a new variant of ransomware called “Sodinokibi"
      author = "Christiaan Beek | McAfee ATR team"
      date = "2019-05-13"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Sodinokibi"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash4 = "9b62f917afa1c1a61e3be0978c8692dac797dd67ce0e5fd2305cc7c6b5fef392"

   strings:

      $x1 = "sodinokibi.exe" fullword wide
      
      $y0 = { 8d 85 6c ff ff ff 50 53 50 e8 62 82 00 00 83 c4 }
      $y1 = { e8 24 ea ff ff ff 75 08 8b ce e8 61 fc ff ff 8b }
      $y2 = { e8 01 64 ff ff ff b6 b0 }

   condition:

      ( uint16(0) == 0x5a4d and 
      filesize < 900KB and 
      pe.imphash() == "672b84df309666b9d7d2bc8cc058e4c2" and 
      ( 8 of them ) and 
      all of ($y*)) or 
      ( all of them )
}

rule Sodinokobi
{
    meta:

        description = "This rule detect Sodinokobi Ransomware in memory in old samples and perhaps future."
        author      = "McAfee ATR team"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransom:W32/Sodinokibi"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        version     = "1.0"
        
    strings:

        $a = { 40 0F B6 C8 89 4D FC 8A 94 0D FC FE FF FF 0F B6 C2 03 C6 0F B6 F0 8A 84 35 FC FE FF FF 88 84 0D FC FE FF FF 88 94 35 FC FE FF FF 0F B6 8C 0D FC FE FF FF }
        $b = { 0F B6 C2 03 C8 8B 45 14 0F B6 C9 8A 8C 0D FC FE FF FF 32 0C 07 88 08 40 89 45 14 8B 45 FC 83 EB 01 75 AA }

    condition:
    
        all of them
}

// From Malpedia
rule win_revil_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-12-22"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.revil"
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
        $sequence_0 = { 8bb694000000 0fa4da0f c1e911 0bc2 c1e30f 8b5508 0bcb }
            // n = 7, score = 4200
            //   8bb694000000         | mov                 esi, dword ptr [esi + 0x94]
            //   0fa4da0f             | shld                edx, ebx, 0xf
            //   c1e911               | shr                 ecx, 0x11
            //   0bc2                 | or                  eax, edx
            //   c1e30f               | shl                 ebx, 0xf
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   0bcb                 | or                  ecx, ebx

        $sequence_1 = { 2345e4 33c7 898bb8000000 8b4de0 8983bc000000 f7d1 }
            // n = 6, score = 4200
            //   2345e4               | and                 eax, dword ptr [ebp - 0x1c]
            //   33c7                 | xor                 eax, edi
            //   898bb8000000         | mov                 dword ptr [ebx + 0xb8], ecx
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   8983bc000000         | mov                 dword ptr [ebx + 0xbc], eax
            //   f7d1                 | not                 ecx

        $sequence_2 = { 8b9f90000000 8bb788000000 8b978c000000 8945e0 8b477c 8945e4 8b8784000000 }
            // n = 7, score = 4200
            //   8b9f90000000         | mov                 ebx, dword ptr [edi + 0x90]
            //   8bb788000000         | mov                 esi, dword ptr [edi + 0x88]
            //   8b978c000000         | mov                 edx, dword ptr [edi + 0x8c]
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   8b477c               | mov                 eax, dword ptr [edi + 0x7c]
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8b8784000000         | mov                 eax, dword ptr [edi + 0x84]

        $sequence_3 = { 50 51 e8???????? 894608 59 59 85c0 }
            // n = 7, score = 4200
            //   50                   | push                eax
            //   51                   | push                ecx
            //   e8????????           |                     
            //   894608               | mov                 dword ptr [esi + 8], eax
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax

        $sequence_4 = { 6802020000 e8???????? 8bf0 59 }
            // n = 4, score = 4200
            //   6802020000           | push                0x202
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   59                   | pop                 ecx

        $sequence_5 = { 55 8bec 83ec10 8d45f0 50 6a0c }
            // n = 6, score = 4200
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec10               | sub                 esp, 0x10
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax
            //   6a0c                 | push                0xc

        $sequence_6 = { 897df8 83f803 7cca 8b4508 5f 5e }
            // n = 6, score = 4200
            //   897df8               | mov                 dword ptr [ebp - 8], edi
            //   83f803               | cmp                 eax, 3
            //   7cca                 | jl                  0xffffffcc
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_7 = { 57 8b7d0c 6685c9 742e 0fb71f 8bd7 6685db }
            // n = 7, score = 4200
            //   57                   | push                edi
            //   8b7d0c               | mov                 edi, dword ptr [ebp + 0xc]
            //   6685c9               | test                cx, cx
            //   742e                 | je                  0x30
            //   0fb71f               | movzx               ebx, word ptr [edi]
            //   8bd7                 | mov                 edx, edi
            //   6685db               | test                bx, bx

        $sequence_8 = { 56 57 8b7d08 33f6 397708 7621 8b470c }
            // n = 7, score = 4200
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   33f6                 | xor                 esi, esi
            //   397708               | cmp                 dword ptr [edi + 8], esi
            //   7621                 | jbe                 0x23
            //   8b470c               | mov                 eax, dword ptr [edi + 0xc]

        $sequence_9 = { ebca 6b45fc0c 8b4d0c 52 ff540808 59 85c0 }
            // n = 7, score = 4200
            //   ebca                 | jmp                 0xffffffcc
            //   6b45fc0c             | imul                eax, dword ptr [ebp - 4], 0xc
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   52                   | push                edx
            //   ff540808             | call                dword ptr [eax + ecx + 8]
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax

    condition:
        7 of them and filesize < 155794432
}
