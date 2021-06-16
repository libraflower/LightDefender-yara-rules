rule win_hancitor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-12-22"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hancitor"
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
        $sequence_0 = { 6824040000 6a00 6a00 6a00 }
            // n = 4, score = 700
            //   6824040000           | push                0x424
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_1 = { 6a00 6a00 6824040000 6a00 }
            // n = 4, score = 700
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6824040000           | push                0x424
            //   6a00                 | push                0

        $sequence_2 = { 68???????? 8d85dcfaffff 50 ff15???????? }
            // n = 4, score = 600
            //   68????????           |                     
            //   8d85dcfaffff         | lea                 eax, [ebp - 0x524]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_3 = { 6800010000 6a40 68???????? e8???????? }
            // n = 4, score = 500
            //   6800010000           | push                0x100
            //   6a40                 | push                0x40
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_4 = { 57 ff7508 ff15???????? 5f 8bc6 5e }
            // n = 6, score = 400
            //   57                   | push                edi
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi

        $sequence_5 = { 8908 8b5518 85d2 740a }
            // n = 4, score = 400
            //   8908                 | mov                 dword ptr [eax], ecx
            //   8b5518               | mov                 edx, dword ptr [ebp + 0x18]
            //   85d2                 | test                edx, edx
            //   740a                 | je                  0xc

        $sequence_6 = { 7448 8b5508 0fbe02 85c0 7504 }
            // n = 5, score = 400
            //   7448                 | je                  0x4a
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   0fbe02               | movsx               eax, byte ptr [edx]
            //   85c0                 | test                eax, eax
            //   7504                 | jne                 6

        $sequence_7 = { a1???????? 33c5 8945fc 6804010000 8d85f8feffff 50 ff15???????? }
            // n = 7, score = 400
            //   a1????????           |                     
            //   33c5                 | xor                 eax, ebp
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   6804010000           | push                0x104
            //   8d85f8feffff         | lea                 eax, [ebp - 0x108]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_8 = { 55 8bec 8b4508 8078013a }
            // n = 4, score = 400
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8078013a             | cmp                 byte ptr [eax + 1], 0x3a

        $sequence_9 = { 8b4804 894de8 8b5508 0355d8 8955f4 8b45f0 83780400 }
            // n = 7, score = 400
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   894de8               | mov                 dword ptr [ebp - 0x18], ecx
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   0355d8               | add                 edx, dword ptr [ebp - 0x28]
            //   8955f4               | mov                 dword ptr [ebp - 0xc], edx
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   83780400             | cmp                 dword ptr [eax + 4], 0

        $sequence_10 = { 50 e8???????? 83c40c c785b4feffff44000000 }
            // n = 4, score = 400
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   c785b4feffff44000000     | mov    dword ptr [ebp - 0x14c], 0x44

        $sequence_11 = { 8b45f4 8b4d10 034c100c 51 e8???????? 83c40c ebb7 }
            // n = 7, score = 400
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   034c100c             | add                 ecx, dword ptr [eax + edx + 0xc]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   ebb7                 | jmp                 0xffffffb9

        $sequence_12 = { 7523 6800040000 e8???????? 83c404 a3???????? }
            // n = 5, score = 400
            //   7523                 | jne                 0x25
            //   6800040000           | push                0x400
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   a3????????           |                     

        $sequence_13 = { 8bec 8b4d08 6a00 6a01 51 8b413c }
            // n = 6, score = 400
            //   8bec                 | mov                 ebp, esp
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   51                   | push                ecx
            //   8b413c               | mov                 eax, dword ptr [ecx + 0x3c]

        $sequence_14 = { c745e801000000 33d2 0f852dffffff 837df800 }
            // n = 4, score = 400
            //   c745e801000000       | mov                 dword ptr [ebp - 0x18], 1
            //   33d2                 | xor                 edx, edx
            //   0f852dffffff         | jne                 0xffffff33
            //   837df800             | cmp                 dword ptr [ebp - 8], 0

        $sequence_15 = { 85c0 7408 8b85f4feffff eb02 33c0 8b4dfc }
            // n = 6, score = 400
            //   85c0                 | test                eax, eax
            //   7408                 | je                  0xa
            //   8b85f4feffff         | mov                 eax, dword ptr [ebp - 0x10c]
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_16 = { 894588 817d886c972d01 7d27 8b45e4 }
            // n = 4, score = 100
            //   894588               | mov                 dword ptr [ebp - 0x78], eax
            //   817d886c972d01       | cmp                 dword ptr [ebp - 0x78], 0x12d976c
            //   7d27                 | jge                 0x29
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]

        $sequence_17 = { 833d????????00 7414 8b45e4 0345c0 }
            // n = 4, score = 100
            //   833d????????00       |                     
            //   7414                 | je                  0x16
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   0345c0               | add                 eax, dword ptr [ebp - 0x40]

        $sequence_18 = { a1???????? 83c044 a3???????? 8b45f8 40 40 8945f8 }
            // n = 7, score = 100
            //   a1????????           |                     
            //   83c044               | add                 eax, 0x44
            //   a3????????           |                     
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   40                   | inc                 eax
            //   40                   | inc                 eax
            //   8945f8               | mov                 dword ptr [ebp - 8], eax

        $sequence_19 = { 8945c0 a1???????? 83c044 a3???????? 8b45a0 05c8d45566 0f8482000000 }
            // n = 7, score = 100
            //   8945c0               | mov                 dword ptr [ebp - 0x40], eax
            //   a1????????           |                     
            //   83c044               | add                 eax, 0x44
            //   a3????????           |                     
            //   8b45a0               | mov                 eax, dword ptr [ebp - 0x60]
            //   05c8d45566           | add                 eax, 0x6655d4c8
            //   0f8482000000         | je                  0x88

        $sequence_20 = { a3???????? 817df8b07d0900 0f8ced000000 a1???????? a3???????? b9382baa99 8d45fc }
            // n = 7, score = 100
            //   a3????????           |                     
            //   817df8b07d0900       | cmp                 dword ptr [ebp - 8], 0x97db0
            //   0f8ced000000         | jl                  0xf3
            //   a1????????           |                     
            //   a3????????           |                     
            //   b9382baa99           | mov                 ecx, 0x99aa2b38
            //   8d45fc               | lea                 eax, [ebp - 4]

        $sequence_21 = { a3???????? 8b45b4 83e803 8945b4 eb22 }
            // n = 5, score = 100
            //   a3????????           |                     
            //   8b45b4               | mov                 eax, dword ptr [ebp - 0x4c]
            //   83e803               | sub                 eax, 3
            //   8945b4               | mov                 dword ptr [ebp - 0x4c], eax
            //   eb22                 | jmp                 0x24

        $sequence_22 = { 83c052 8945cc 8365e400 c745bc0a000000 }
            // n = 4, score = 100
            //   83c052               | add                 eax, 0x52
            //   8945cc               | mov                 dword ptr [ebp - 0x34], eax
            //   8365e400             | and                 dword ptr [ebp - 0x1c], 0
            //   c745bc0a000000       | mov                 dword ptr [ebp - 0x44], 0xa

        $sequence_23 = { a1???????? 83c05b a3???????? a1???????? 0345cc a3???????? 817df8b07d0900 }
            // n = 7, score = 100
            //   a1????????           |                     
            //   83c05b               | add                 eax, 0x5b
            //   a3????????           |                     
            //   a1????????           |                     
            //   0345cc               | add                 eax, dword ptr [ebp - 0x34]
            //   a3????????           |                     
            //   817df8b07d0900       | cmp                 dword ptr [ebp - 8], 0x97db0

    condition:
        7 of them and filesize < 106496
}

  
rule Hancitor
{
    meta:
        author = "kevoreilly"
        description = "Hancitor Payload"
        cape_type = "Hancitor Payload"
    strings:
        $decrypt1 = {33 C9 03 D6 C7 45 FC ?? ?? ?? ?? 8B 70 10 85 F6 74 12 90 8B C1 83 E0 03 8A 44 05 FC 30 04 11 41 3B CE 72 EF}
        $decrypt2 = {B9 08 00 00 00 8B 75 08 83 C4 04 8B F8 3B D1 76 10 8B C1 83 E0 07 8A 04 30 30 04 31 41 3B CA 72 F0 8D 45 FC}
        $decrypt3 = {8B 45 FC 33 D2 B9 08 00 00 00 F7 F1 8B 45 08 0F BE 0C 10 8B 55 08 03 55 FC 0F BE 02 33 C1 8B 4D 08 03 4D FC 88 01 EB C7}
    condition:
        uint16(0) == 0x5A4D and (any of ($decrypt*))
}

rule hancitor {
	meta:
		description = "Memory string yara for Hancitor"
		author = "J from THL <j@techhelplist.com>"
		reference1 = "https://researchcenter.paloaltonetworks.com/2018/02/threat-brief-hancitor-actors/"
		reference2 = "https://www.virustotal.com/#/file/43e17f30b78c085e9bda8cadf5063cd5cec9edaa7441594ba1fe51391cc1c486/"
		reference3 = "https://www.virustotal.com/#/file/d135f03b9fdc709651ac9d0264e155c5580b072577a8ff24c90183b126b5e12a/"
		date = "2018-09-18"
		maltype1 = "Botnet"
		filetype = "memory"

	strings:
		$a = "GUID="	ascii
                $b = "&BUILD="	ascii
                $c = "&INFO="	ascii
                $d = "&IP="	ascii
                $e = "&TYPE=" 	ascii
                $f = "php|http"	ascii
		$g = "GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d" ascii fullword


	condition:
		5 of ($a,$b,$c,$d,$e,$f) or $g

}