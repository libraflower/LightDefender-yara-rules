rule Azorult
{
    meta:
        author = "kevoreilly"
        description = "Azorult Payload"
        cape_type = "Azorult Payload"
    strings:
        $code1 = {C7 07 3C 00 00 00 8D 45 80 89 47 04 C7 47 08 20 00 00 00 8D 85 80 FE FF FF 89 47 10 C7 47 14 00 01 00 00 8D 85 00 FE FF FF 89 47 1C C7 47 20 80 00 00 00 8D 85 80 FD FF FF 89 47 24 C7 47 28 80 00 00 00 8D 85 80 F5 FF FF 89 47 2C C7 47 30 00 08 00 00 8D 85 80 F1 FF FF 89 47 34 C7 47 38 00 04 00 00 57 68 00 00 00 90}
        $string1 = "SELECT DATETIME( ((visits.visit_time/1000000)-11644473600),\"unixepoch\")"
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule Azorult {
          meta:
            description = "detect Azorult in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $v1 = "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.1)"
            $v2 = "http://ip-api.com/json"
            $v3 = { c6 07 1e c6 47 01 15 c6 47 02 34 }

          condition: all of them
}

rule win_azorult_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-12-01"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.5.0"
        tool_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.azorult"
        malpedia_rule_date = "20201127"
        malpedia_hash = "ae61de407d8ec67cdbe44187237e174f42b42c47"
        malpedia_version = ""
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
        $sequence_0 = { 8bd8 85db 7447 8b45fc e8???????? 03d8 8d45f8 }
            // n = 7, score = 1200
            //   8bd8                 | mov                 ebx, eax
            //   85db                 | test                ebx, ebx
            //   7447                 | je                  0x49
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   e8????????           |                     
            //   03d8                 | add                 ebx, eax
            //   8d45f8               | lea                 eax, [ebp - 8]

        $sequence_1 = { 8d45e4 8b55f8 8a543201 885001 }
            // n = 4, score = 1200
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   8a543201             | mov                 dl, byte ptr [edx + esi + 1]
            //   885001               | mov                 byte ptr [eax + 1], dl

        $sequence_2 = { 33c9 ba00040000 e8???????? 6a00 }
            // n = 4, score = 1200
            //   33c9                 | xor                 ecx, ecx
            //   ba00040000           | mov                 edx, 0x400
            //   e8????????           |                     
            //   6a00                 | push                0

        $sequence_3 = { 895dd8 895ddc 895de0 895dec 894df4 }
            // n = 5, score = 1200
            //   895dd8               | mov                 dword ptr [ebp - 0x28], ebx
            //   895ddc               | mov                 dword ptr [ebp - 0x24], ebx
            //   895de0               | mov                 dword ptr [ebp - 0x20], ebx
            //   895dec               | mov                 dword ptr [ebp - 0x14], ebx
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx

        $sequence_4 = { e8???????? eb07 8bc3 e8???????? 81c404020000 5b c3 }
            // n = 7, score = 1200
            //   e8????????           |                     
            //   eb07                 | jmp                 9
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     
            //   81c404020000         | add                 esp, 0x204
            //   5b                   | pop                 ebx
            //   c3                   | ret                 

        $sequence_5 = { 59 648910 e9???????? 8d45f4 50 8b45e0 }
            // n = 6, score = 1200
            //   59                   | pop                 ecx
            //   648910               | mov                 dword ptr fs:[eax], edx
            //   e9????????           |                     
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]

        $sequence_6 = { 8d859cfdffff 50 8b45ec 50 }
            // n = 4, score = 1200
            //   8d859cfdffff         | lea                 eax, [ebp - 0x264]
            //   50                   | push                eax
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   50                   | push                eax

        $sequence_7 = { 68???????? 8d8594fdffff ba04000000 e8???????? }
            // n = 4, score = 1200
            //   68????????           |                     
            //   8d8594fdffff         | lea                 eax, [ebp - 0x26c]
            //   ba04000000           | mov                 edx, 4
            //   e8????????           |                     

        $sequence_8 = { 7506 ff05???????? 56 e8???????? }
            // n = 4, score = 900
            //   7506                 | jne                 8
            //   ff05????????         |                     
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_9 = { 53 e8???????? 59 56 e8???????? 59 8bc7 }
            // n = 7, score = 900
            //   53                   | push                ebx
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8bc7                 | mov                 eax, edi

        $sequence_10 = { e8???????? 59 8b45f4 40 }
            // n = 4, score = 600
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   40                   | inc                 eax

        $sequence_11 = { 85db 7404 8bc3 eb07 }
            // n = 4, score = 500
            //   85db                 | test                ebx, ebx
            //   7404                 | je                  6
            //   8bc3                 | mov                 eax, ebx
            //   eb07                 | jmp                 9

        $sequence_12 = { 7446 33c0 50 50 50 50 6aff }
            // n = 7, score = 200
            //   7446                 | je                  0x48
            //   33c0                 | xor                 eax, eax
            //   50                   | push                eax
            //   50                   | push                eax
            //   50                   | push                eax
            //   50                   | push                eax
            //   6aff                 | push                -1

        $sequence_13 = { 8b7908 8b490c 33f8 6a04 33c8 }
            // n = 5, score = 200
            //   8b7908               | mov                 edi, dword ptr [ecx + 8]
            //   8b490c               | mov                 ecx, dword ptr [ecx + 0xc]
            //   33f8                 | xor                 edi, eax
            //   6a04                 | push                4
            //   33c8                 | xor                 ecx, eax

        $sequence_14 = { e8???????? 8d85acfeffff c785acfeffff1c010000 50 ff15???????? }
            // n = 5, score = 200
            //   e8????????           |                     
            //   8d85acfeffff         | lea                 eax, [ebp - 0x154]
            //   c785acfeffff1c010000     | mov    dword ptr [ebp - 0x154], 0x11c
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_15 = { 3bc3 754b 8bf7 85db 7e45 }
            // n = 5, score = 200
            //   3bc3                 | cmp                 eax, ebx
            //   754b                 | jne                 0x4d
            //   8bf7                 | mov                 esi, edi
            //   85db                 | test                ebx, ebx
            //   7e45                 | jle                 0x47

    condition:
        7 of them and filesize < 1753088
}
