import "pe"
// aka. Ghost RAT, Gh0st RAT, PCRat
rule Farfli {
    meta:
        author = "ditekSHen"
        description = "Detects Farfli backdoor"
        cape_type = "Farfli Payload"
    strings:
        $s1 = "%ProgramFiles%\\Google\\" fullword ascii
        $s2 = "%s\\%d.bak" fullword ascii
        $s3 = "%s Win7" fullword ascii
        $s4 = "%s:%d:%s" fullword ascii
        $s5 = "C:\\2.txt" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule win_ghost_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-06-10"
        version = "1"
        description = "Detects win.ghost_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ghost_rat"
        malpedia_rule_date = "20210604"
        malpedia_hash = "be09d5d71e77373c0f538068be31a2ad4c69cfbd"
        malpedia_version = "20210616"
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
        $sequence_0 = { 6a01 56 ff15???????? 5e c20800 }
            // n = 5, score = 500
            //   6a01                 | push                1
            //   56                   | push                esi
            //   ff15????????         |                     
            //   5e                   | pop                 esi
            //   c20800               | ret                 8

        $sequence_1 = { 8bd9 e8???????? 8b4d08 3bc8 }
            // n = 4, score = 500
            //   8bd9                 | mov                 ebx, ecx
            //   e8????????           |                     
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   3bc8                 | cmp                 ecx, eax

        $sequence_2 = { 8b400c 85c0 7505 a1???????? 50 8bce e8???????? }
            // n = 7, score = 500
            //   8b400c               | mov                 eax, dword ptr [eax + 0xc]
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7
            //   a1????????           |                     
            //   50                   | push                eax
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_3 = { 6a6b 8bce e8???????? 5f 5e }
            // n = 5, score = 400
            //   6a6b                 | push                0x6b
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_4 = { 8b06 6aff 50 ff15???????? 8b0e 51 }
            // n = 6, score = 400
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   6aff                 | push                -1
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   51                   | push                ecx

        $sequence_5 = { c20400 894df4 c745f800000000 df6df4 83ec08 dc0d???????? dd1c24 }
            // n = 7, score = 400
            //   c20400               | ret                 4
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0
            //   df6df4               | fild                qword ptr [ebp - 0xc]
            //   83ec08               | sub                 esp, 8
            //   dc0d????????         |                     
            //   dd1c24               | fstp                qword ptr [esp]

        $sequence_6 = { 5b 8be5 5d c20400 894df4 c745f800000000 }
            // n = 6, score = 400
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0

        $sequence_7 = { 50 6800000080 ff15???????? 85c0 7407 32c0 e9???????? }
            // n = 7, score = 300
            //   50                   | push                eax
            //   6800000080           | push                0x80000000
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   32c0                 | xor                 al, al
            //   e9????????           |                     

        $sequence_8 = { 84c0 7505 83ceff eb2c }
            // n = 4, score = 300
            //   84c0                 | test                al, al
            //   7505                 | jne                 7
            //   83ceff               | or                  esi, 0xffffffff
            //   eb2c                 | jmp                 0x2e

        $sequence_9 = { 8dbd85feffff f3ab 66ab aa }
            // n = 4, score = 300
            //   8dbd85feffff         | lea                 edi, dword ptr [ebp - 0x17b]
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al

        $sequence_10 = { f3a4 ff15???????? 8bf0 83c40c 46 750b }
            // n = 6, score = 300
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   83c40c               | add                 esp, 0xc
            //   46                   | inc                 esi
            //   750b                 | jne                 0xd

        $sequence_11 = { 68???????? 6a00 6a00 e8???????? 8b8e549f0000 }
            // n = 5, score = 300
            //   68????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   e8????????           |                     
            //   8b8e549f0000         | mov                 ecx, dword ptr [esi + 0x9f54]

        $sequence_12 = { e9???????? 8d45dc 50 681f000200 }
            // n = 4, score = 300
            //   e9????????           |                     
            //   8d45dc               | lea                 eax, dword ptr [ebp - 0x24]
            //   50                   | push                eax
            //   681f000200           | push                0x2001f

        $sequence_13 = { 68???????? 50 6802000080 e8???????? 83c41c 5f }
            // n = 6, score = 300
            //   68????????           |                     
            //   50                   | push                eax
            //   6802000080           | push                0x80000002
            //   e8????????           |                     
            //   83c41c               | add                 esp, 0x1c
            //   5f                   | pop                 edi

        $sequence_14 = { 57 8bfe f2ae f7d1 49 7509 5f }
            // n = 7, score = 300
            //   57                   | push                edi
            //   8bfe                 | mov                 edi, esi
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx
            //   7509                 | jne                 0xb
            //   5f                   | pop                 edi

        $sequence_15 = { 8365fc00 ff7508 ff15???????? 40 50 ff15???????? 59 }
            // n = 7, score = 300
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   40                   | inc                 eax
            //   50                   | push                eax
            //   ff15????????         |                     
            //   59                   | pop                 ecx

        $sequence_16 = { 8bce ff75e8 e8???????? 8bce e8???????? }
            // n = 5, score = 300
            //   8bce                 | mov                 ecx, esi
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   e8????????           |                     
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_17 = { 8b5c2408 55 8b6c2410 56 8b742418 57 3bee }
            // n = 7, score = 300
            //   8b5c2408             | mov                 ebx, dword ptr [esp + 8]
            //   55                   | push                ebp
            //   8b6c2410             | mov                 ebp, dword ptr [esp + 0x10]
            //   56                   | push                esi
            //   8b742418             | mov                 esi, dword ptr [esp + 0x18]
            //   57                   | push                edi
            //   3bee                 | cmp                 ebp, esi

        $sequence_18 = { 6a00 50 e8???????? 83c40c ff7508 6a40 ff15???????? }
            // n = 7, score = 300
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   ff7508               | push                dword ptr [ebp + 8]
            //   6a40                 | push                0x40
            //   ff15????????         |                     

        $sequence_19 = { 6a01 ff7620 ff15???????? 8b4e04 e8???????? 33c0 }
            // n = 6, score = 300
            //   6a01                 | push                1
            //   ff7620               | push                dword ptr [esi + 0x20]
            //   ff15????????         |                     
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax

        $sequence_20 = { e8???????? 59 83c8ff e9???????? 8b45fc }
            // n = 5, score = 300
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   83c8ff               | or                  eax, 0xffffffff
            //   e9????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_21 = { ff7510 ff75dc ff15???????? 85c0 7507 c745e401000000 834dfcff }
            // n = 7, score = 300
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff75dc               | push                dword ptr [ebp - 0x24]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7507                 | jne                 9
            //   c745e401000000       | mov                 dword ptr [ebp - 0x1c], 1
            //   834dfcff             | or                  dword ptr [ebp - 4], 0xffffffff

        $sequence_22 = { c745e0867f0000 c745e4837f0000 c745e8857f0000 c745ec827f0000 }
            // n = 4, score = 200
            //   c745e0867f0000       | mov                 dword ptr [ebp - 0x20], 0x7f86
            //   c745e4837f0000       | mov                 dword ptr [ebp - 0x1c], 0x7f83
            //   c745e8857f0000       | mov                 dword ptr [ebp - 0x18], 0x7f85
            //   c745ec827f0000       | mov                 dword ptr [ebp - 0x14], 0x7f82

        $sequence_23 = { c745e8857f0000 c745ec827f0000 c745f0847f0000 c745f4047f0000 }
            // n = 4, score = 200
            //   c745e8857f0000       | mov                 dword ptr [ebp - 0x18], 0x7f85
            //   c745ec827f0000       | mov                 dword ptr [ebp - 0x14], 0x7f82
            //   c745f0847f0000       | mov                 dword ptr [ebp - 0x10], 0x7f84
            //   c745f4047f0000       | mov                 dword ptr [ebp - 0xc], 0x7f04

        $sequence_24 = { 83e9fc c7014c696272 83e9fc c70161727941 }
            // n = 4, score = 200
            //   83e9fc               | sub                 ecx, -4
            //   c7014c696272         | mov                 dword ptr [ecx], 0x7262694c
            //   83e9fc               | sub                 ecx, -4
            //   c70161727941         | mov                 dword ptr [ecx], 0x41797261

        $sequence_25 = { 813f6b006500 7406 813f4b004500 75e8 }
            // n = 4, score = 200
            //   813f6b006500         | cmp                 dword ptr [edi], 0x65006b
            //   7406                 | je                  8
            //   813f4b004500         | cmp                 dword ptr [edi], 0x45004b
            //   75e8                 | jne                 0xffffffea

        $sequence_26 = { 8b761c 8b4608 8b7e20 8b36 813f6b006500 7406 }
            // n = 6, score = 200
            //   8b761c               | mov                 esi, dword ptr [esi + 0x1c]
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   8b7e20               | mov                 edi, dword ptr [esi + 0x20]
            //   8b36                 | mov                 esi, dword ptr [esi]
            //   813f6b006500         | cmp                 dword ptr [edi], 0x65006b
            //   7406                 | je                  8

        $sequence_27 = { 898d44ffffff 8b9544ffffff 33c0 668b4206 }
            // n = 4, score = 100
            //   898d44ffffff         | mov                 dword ptr [ebp - 0xbc], ecx
            //   8b9544ffffff         | mov                 edx, dword ptr [ebp - 0xbc]
            //   33c0                 | xor                 eax, eax
            //   668b4206             | mov                 ax, word ptr [edx + 6]

        $sequence_28 = { 8b5104 83ea08 d1ea 3955f4 7749 8b45f0 33c9 }
            // n = 7, score = 100
            //   8b5104               | mov                 edx, dword ptr [ecx + 4]
            //   83ea08               | sub                 edx, 8
            //   d1ea                 | shr                 edx, 1
            //   3955f4               | cmp                 dword ptr [ebp - 0xc], edx
            //   7749                 | ja                  0x4b
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   33c9                 | xor                 ecx, ecx

        $sequence_29 = { 8945ec 8b8d58ffffff 034dec 66c7014343 8b9558ffffff 8b423c }
            // n = 6, score = 100
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   8b8d58ffffff         | mov                 ecx, dword ptr [ebp - 0xa8]
            //   034dec               | add                 ecx, dword ptr [ebp - 0x14]
            //   66c7014343           | mov                 word ptr [ecx], 0x4343
            //   8b9558ffffff         | mov                 edx, dword ptr [ebp - 0xa8]
            //   8b423c               | mov                 eax, dword ptr [edx + 0x3c]

        $sequence_30 = { 8b8dfcfeffff 51 ff9514ffffff 83c40c e9???????? 8b957cffffff 83ba8800000000 }
            // n = 7, score = 100
            //   8b8dfcfeffff         | mov                 ecx, dword ptr [ebp - 0x104]
            //   51                   | push                ecx
            //   ff9514ffffff         | call                dword ptr [ebp - 0xec]
            //   83c40c               | add                 esp, 0xc
            //   e9????????           |                     
            //   8b957cffffff         | mov                 edx, dword ptr [ebp - 0x84]
            //   83ba8800000000       | cmp                 dword ptr [edx + 0x88], 0

        $sequence_31 = { 41 ebc0 8d8d98ffffff c7014c6f6164 }
            // n = 4, score = 100
            //   41                   | inc                 ecx
            //   ebc0                 | jmp                 0xffffffc2
            //   8d8d98ffffff         | lea                 ecx, dword ptr [ebp - 0x68]
            //   c7014c6f6164         | mov                 dword ptr [ecx], 0x64616f4c

    condition:
        7 of them and filesize < 357376
}

rule Backdoor_Farfli {
   meta:
      description = "Backdoor.Farfli"
      author = "LightDefender"
      date = "2021-07-04"
      hash1 = "231994c79a1fafe117deeb111a6ba3c026afa18a1e89522b8f81cc2f68dfd10a"
   strings:
      $a1 = "SpywareTerminatorShield" fullword ascii
      $a2 = "AVWatchService" fullword ascii
      $a3 = "ddos\\Server\\Release\\Xy" fullword ascii
      $a4 = "cmd.exe /c net user guest /active:yes && net user guest ratpp && net localgroup administrators guest /add && net guest admin" fullword ascii
      $a5 = "activatibleClassId" fullword wide
      $s1 = "rtvscan" fullword ascii
      $s2 = "Sophos" fullword ascii
      $s3 = "knsdtray" fullword ascii
      $s4 = "beikesan" fullword ascii
      $s5 = "acsseeis" fullword ascii
      $s6 = "ajzpxwgh" fullword ascii
      $s7 = "kxetray" fullword ascii
      $s8 = "avcenter" fullword ascii
      $s9 = "avgwdsvc" fullword ascii
      $s10 = "fsavgui" fullword ascii
      $s11 = "safedog" fullword ascii
      $s12 = "mssecess" fullword ascii
      $s13 = "kpfwtray" fullword ascii
      $s14 = "rfwmain" fullword ascii
      $s15 = "spidernt" fullword ascii
      $s16 = "avgaurd" fullword ascii
      $s17 = "nspupsvc" fullword ascii
      $s18 = "qayouuuq" fullword ascii
      $s19 = "auqyiyauekwamuyiie" fullword ascii
      $s20 = "fuckyou" fullword ascii
      $s21 = "SYSTEM\\Clore" fullword ascii
      $s22 = "szDownRun" fullword ascii
      $s23 = "BKavService" fullword ascii
      $s24 = "QUHLPSVC" fullword ascii
      $s25 = "QQPCRTP" fullword ascii
      $s26 = "TMBMSRV" fullword ascii
      $s27 = "MsMpEng" fullword ascii
      $s28 = "\\\\.\\PHYSICALDRIVE0" fullword ascii
      $s29 = "VIRUSfighter" fullword ascii
      $s30 = "Mongoosa" fullword ascii
      $s31 = "Lavasoft" fullword ascii
      $s32 = "Immunet" fullword ascii
      $s33 = "smtp.china.com" fullword ascii
      $s34 = "Local\\SM0:%d:%d:%hs" fullword wide
      $s35 = ".data$r$brc" fullword ascii
      $s36 = ".data$dk00" fullword ascii
      $s37 = ".data$dk00$brc" fullword ascii
      $s38 = "select * from mail ORDER BY mail_id ASC" fullword ascii
      $s39 = ".data$zz" fullword ascii
      $s40 = ".data$00" fullword ascii
      $s41 = "SUBJECT: <%s>" fullword ascii
      $s42 = "WilError_03" fullword ascii
   condition:
      uint16(0) == 0x5a4d and (1 of ($a*) and 10 of ($s*))
}

rule Backdoor_Farfli_July17 {
   meta:
      description = "Backdoor.Farfli"
      author = "LightDefender"
      date = "2021-07-17"
      hash1 = "608a2479b8855c3ed60503e8cfcb88b25d3a37c486c7c11c07d031569363f4f8"
   strings:
      $s1 = "yzsaaa@163.com" fullword wide
      $s2 = " Base Class Descriptor at (" fullword ascii
      $s3 = {14 02 48 65 61 70 44 65 73 74 72 6F 79 00 12 02 48 65 61 70 43 72 65 61 74 65 00 00 B9 01 47 65 74 53 74 64 48 61 6E 64 6C 65 00 00 F6 00 46 72 65 65 45 6E 76 69 72 6F 6E 6D 65 6E 74 53 74 72 69 6E 67 73 41 00 55 01 47 65 74 45 6E 76 69 72 6F 6E 6D 65 6E 74 53 74 72 69 6E 67 73 00 F7 00 46 72 65 65 45 6E 76 69 72 6F 6E 6D 65 6E 74 53 74 72 69 6E 67 73 57 00 57 01 47 65 74 45 6E 76 69 72 6F 6E 6D 65 6E 74 53 74 72 69 6E 67 73 57 00 00 24 03 53 65 74 48 61 6E 64 6C 65 43 6F 75 6E 74 00 00 66 01 47 65 74 46 69 6C 65 54 79 70 65 00 A3 02 51 75 65 72 79 50 65 72 66 6F 72 6D 61 6E 63 65 43 6F 75 6E 74 65 72 00 CA 01 47 65 74 53 79 73 74 65 6D 54 69 6D 65 41 73 46 69 6C 65 54 69 6D 65 00}
      $s4 = {00 00 37 03 53 65 74 53 74 64 48 61 6E 64 6C 65 00 00 99 03 57 72 69 74 65 43 6F 6E 73 6F 6C 65 41 00 35 01 47 65 74 43 6F 6E 73 6F 6C 65 4F 75 74 70 75 74 43 50 00 00 A3 03 57 72 69 74 65 43 6F 6E 73 6F 6C 65 57 00 13 03 53 65 74 45 6E 76 69 72 6F 6E 6D 65 6E 74 56 61 72 69 61 62 6C 65 41 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00}
      $s5 = {00 93 01 49 6E 76 61 6C 69 64 61 74 65 52 65 63 74 00}
      $s6 = {00 40 00 43 6C 69 65 6E 74 54 6F 53 63 72 65 65 6E 00 00}
   condition:
      uint16(0) == 0x5a4d and 5 of them
}
