rule PhantomNet {
   meta:
      description = "PhantomNet"
      date = "2021-06-13"
      author = "LightDefender"
      hash1 = "603881f4c80e9910ab22f39717e8b296910bff08cd0f25f78d5bff1ae0dce5d7"
   strings:
      $s1 = {00 4D 52 47 4F 2E 64 6C 6C 00 45 6E 74 65 72 79 00}
   condition:
      uint16(0) == 0x5a4d and all of them
}

rule win_smanager_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-12-22"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.smanager"
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
        $sequence_0 = { 75ea 8b4dfc be04000000 03cb 2bf3 894dfc 85f6 }
            // n = 7, score = 100
            //   75ea                 | jne                 0xffffffec
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   be04000000           | mov                 esi, 4
            //   03cb                 | add                 ecx, ebx
            //   2bf3                 | sub                 esi, ebx
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   85f6                 | test                esi, esi

        $sequence_1 = { 83c404 ff75bc ff15???????? e9???????? c645fc01 }
            // n = 5, score = 100
            //   83c404               | add                 esp, 4
            //   ff75bc               | push                dword ptr [ebp - 0x44]
            //   ff15????????         |                     
            //   e9????????           |                     
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1

        $sequence_2 = { 8b08 8d55b0 52 8d55dc 52 }
            // n = 5, score = 100
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8d55b0               | lea                 edx, [ebp - 0x50]
            //   52                   | push                edx
            //   8d55dc               | lea                 edx, [ebp - 0x24]
            //   52                   | push                edx

        $sequence_3 = { 3d70001100 7430 3d78ba7c54 7554 85c9 7450 8b4510 }
            // n = 7, score = 100
            //   3d70001100           | cmp                 eax, 0x110070
            //   7430                 | je                  0x32
            //   3d78ba7c54           | cmp                 eax, 0x547cba78
            //   7554                 | jne                 0x56
            //   85c9                 | test                ecx, ecx
            //   7450                 | je                  0x52
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]

        $sequence_4 = { 50 ff15???????? 6a2c e8???????? 8bf0 83c404 8bce }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   6a2c                 | push                0x2c
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c404               | add                 esp, 4
            //   8bce                 | mov                 ecx, esi

        $sequence_5 = { 8bf8 83c102 51 6a00 57 e8???????? }
            // n = 6, score = 100
            //   8bf8                 | mov                 edi, eax
            //   83c102               | add                 ecx, 2
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_6 = { e8???????? 0f57c0 a3???????? 83c404 0f1100 0f114010 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   0f57c0               | xorps               xmm0, xmm0
            //   a3????????           |                     
            //   83c404               | add                 esp, 4
            //   0f1100               | movups              xmmword ptr [eax], xmm0
            //   0f114010             | movups              xmmword ptr [eax + 0x10], xmm0
            //   e8????????           |                     

        $sequence_7 = { 81784808950210 7409 ff7048 e8???????? 59 c70701000000 8bcf }
            // n = 7, score = 100
            //   81784808950210       | cmp                 dword ptr [eax + 0x48], 0x10029508
            //   7409                 | je                  0xb
            //   ff7048               | push                dword ptr [eax + 0x48]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   c70701000000         | mov                 dword ptr [edi], 1
            //   8bcf                 | mov                 ecx, edi

        $sequence_8 = { 8901 66c7400c0101 c3 55 8bec 6aff }
            // n = 6, score = 100
            //   8901                 | mov                 dword ptr [ecx], eax
            //   66c7400c0101         | mov                 word ptr [eax + 0xc], 0x101
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   6aff                 | push                -1

        $sequence_9 = { 85ff 7515 33c0 5f 5e }
            // n = 5, score = 100
            //   85ff                 | test                edi, edi
            //   7515                 | jne                 0x17
            //   33c0                 | xor                 eax, eax
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

    condition:
        7 of them and filesize < 398336
}
