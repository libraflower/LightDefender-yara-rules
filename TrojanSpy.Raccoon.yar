rule win_raccoon_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-12-22"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.raccoon"
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
        $sequence_0 = { 894608 8b4514 894d10 8bce 89460c 895514 }
            // n = 6, score = 2000
            //   894608               | mov                 dword ptr [esi + 8], eax
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   894d10               | mov                 dword ptr [ebp + 0x10], ecx
            //   8bce                 | mov                 ecx, esi
            //   89460c               | mov                 dword ptr [esi + 0xc], eax
            //   895514               | mov                 dword ptr [ebp + 0x14], edx

        $sequence_1 = { 56 8bf1 57 8d7ee0 e8???????? 8365fc00 }
            // n = 6, score = 2000
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   57                   | push                edi
            //   8d7ee0               | lea                 edi, [esi - 0x20]
            //   e8????????           |                     
            //   8365fc00             | and                 dword ptr [ebp - 4], 0

        $sequence_2 = { c3 55 8bec 81ec98000000 8365b000 53 56 }
            // n = 7, score = 2000
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec98000000         | sub                 esp, 0x98
            //   8365b000             | and                 dword ptr [ebp - 0x50], 0
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_3 = { e8???????? 8bd8 83c410 85db 0f84d5000000 8b4df8 }
            // n = 6, score = 2000
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   83c410               | add                 esp, 0x10
            //   85db                 | test                ebx, ebx
            //   0f84d5000000         | je                  0xdb
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]

        $sequence_4 = { 0f434dd8 51 56 e8???????? }
            // n = 4, score = 2000
            //   0f434dd8             | cmovae              ecx, dword ptr [ebp - 0x28]
            //   51                   | push                ecx
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_5 = { 33c9 57 390e 7411 }
            // n = 4, score = 2000
            //   33c9                 | xor                 ecx, ecx
            //   57                   | push                edi
            //   390e                 | cmp                 dword ptr [esi], ecx
            //   7411                 | je                  0x13

        $sequence_6 = { 57 8bfa 894dfc 0fb6460f }
            // n = 4, score = 2000
            //   57                   | push                edi
            //   8bfa                 | mov                 edi, edx
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   0fb6460f             | movzx               eax, byte ptr [esi + 0xf]

        $sequence_7 = { 56 ff15???????? 8b4df4 56 }
            // n = 4, score = 2000
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   56                   | push                esi

        $sequence_8 = { 8945fc 894e10 c746140f000000 880e 8945f0 }
            // n = 5, score = 2000
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   894e10               | mov                 dword ptr [esi + 0x10], ecx
            //   c746140f000000       | mov                 dword ptr [esi + 0x14], 0xf
            //   880e                 | mov                 byte ptr [esi], cl
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax

        $sequence_9 = { e9???????? 8b450c 8d4de0 8a00 }
            // n = 4, score = 2000
            //   e9????????           |                     
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8d4de0               | lea                 ecx, [ebp - 0x20]
            //   8a00                 | mov                 al, byte ptr [eax]

    condition:
        7 of them and filesize < 1212416
}

rule MALWARE_Win_Raccoon {
    meta:
        author = "ditekSHen"
        description = "Detects Raccoon/Racealer infostealer"
        clamav_sig = "MALWARE.Win.Trojan.Raccoon"
    strings:
        $s1 = "endptr == token_buffer.data() + token_buffer.size()" fullword wide
        $s2 = "inetcomm server passwords" fullword wide
        $s3 = "\\json.hpp" wide
        $s4 = "CredEnumerateW" fullword ascii
        $s5 = "Microsoft_WinInet_" fullword wide
        $s6 = "already connected" fullword ascii
        $s7 = "copy_file" fullword ascii
        $s8 = "\"; filename=\"" fullword ascii
        $s9 = "%[^:]://%[^/]%[^" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 8 of them
}
rule TrojanSpy_Raccoon_July_21 {
   meta:
      author = "LightDefender"
      date = "2021-07-21"
      hash1 = "0042db3f1d304c60dc3d50fb26fcc87cea1b8f2eb15132429588d3a0f4bae296"
   strings:
      $op1 = {558BEC833D94????000074196894????00E8C?2D}
      $op2 = {8B45}
      $op3 = {558BEC5156578BF96A008D4DFCE8??0E00008B47}
      $op4 = {CCCCCCCCCCCCCCCCCCCCCC8B5424048B4C2408F7}
   condition:
      uint16(0) == 0x5a4d and 3 of them
 }

rule TrojanSpy_Raccoon_July_28 {
   meta:
      description = "Ransom.Cerber"
      author = "LightDefender"
      date = "2021-07-28"
      hash1 = "7b608f567cdbb7a9ccce2a9937b34bb3b73e178efc3d2b9bc29e5fe905462bee"
   strings:
      $op1 = {558BEC83EC40837D0C00751C837D10007616837D}
      $op2 = {8B4508C7000000000033C0E9D1020000837D0800}
      $op3 = {558BEC6AFF68?89?420064A1000000005083EC24}
      $op4 = {558BEC51894DFC8B45FCC6400C00837D08000F85}
      $op5 = {CCCCCCCCCCCCCCCCCCCCCCCCCCCC8BFF558BEC}
      $op6 = {83EC08535657A1????43003145F833C5508D45F0}
   condition:
      uint16(0) == 0x5a4d and 5 of them
 }
