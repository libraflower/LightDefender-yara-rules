rule Fusion
{
meta:
	description = "Identifies Fusion ransomware, Go variant of Nemty/Nefilim."
	author = "@bartblaze"
	date = "2021-06"
	tlp = "White"

strings:
	$s1 = "main.getdrives" ascii wide
	$s2 = "main.SaveNote" ascii wide
	$s3 = "main.FileSearch" ascii wide
	$s4 = "main.BytesToPublicKey" ascii wide
	$s5 = "main.GenerateRandomBytes" ascii wide

	$x1 = /Fa[i1]led to fi.Close/ ascii wide
	$x2 = /Fa[i1]led to fi2.Close/ ascii wide
	$x3 = /Fa[i1]led to get stat/ ascii wide
	$x4 = /Fa[i1]led to os.OpenFile/ ascii wide

	$pdb1 = "C:/OpenServer/domains/build/aes.go" ascii wide
	$pdb2 = "C:/Users/eugene/Desktop/test go/test.go" ascii wide
	//C:/Users/eugene/Desktop/web/src/aes_sGHR6SQYlVm0COgz.go
	$pdb3 = "C:/Users/eugene/Desktop/web/src/aes_" ascii wide

condition:
	4 of ($s*) or 3 of ($x*) or any of ($pdb*)
}

rule win_nemty_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-12-22"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nemty"
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
        $sequence_0 = { 7406 53 e8???????? 8347041c 5e 5b c3 }
            // n = 7, score = 300
            //   7406                 | je                  8
            //   53                   | push                ebx
            //   e8????????           |                     
            //   8347041c             | add                 dword ptr [edi + 4], 0x1c
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c3                   | ret                 

        $sequence_1 = { 8bcf 8b35???????? 03f1 83f810 }
            // n = 4, score = 300
            //   8bcf                 | mov                 ecx, edi
            //   8b35????????         |                     
            //   03f1                 | add                 esi, ecx
            //   83f810               | cmp                 eax, 0x10

        $sequence_2 = { 83f906 7524 83f801 7507 }
            // n = 4, score = 300
            //   83f906               | cmp                 ecx, 6
            //   7524                 | jne                 0x26
            //   83f801               | cmp                 eax, 1
            //   7507                 | jne                 9

        $sequence_3 = { 83f803 7515 be???????? eb13 83f90a 7509 be???????? }
            // n = 7, score = 300
            //   83f803               | cmp                 eax, 3
            //   7515                 | jne                 0x17
            //   be????????           |                     
            //   eb13                 | jmp                 0x15
            //   83f90a               | cmp                 ecx, 0xa
            //   7509                 | jne                 0xb
            //   be????????           |                     

        $sequence_4 = { be???????? 8bca 3bc7 7302 8bce 030d???????? }
            // n = 6, score = 300
            //   be????????           |                     
            //   8bca                 | mov                 ecx, edx
            //   3bc7                 | cmp                 eax, edi
            //   7302                 | jae                 4
            //   8bce                 | mov                 ecx, esi
            //   030d????????         |                     

        $sequence_5 = { ffb5f8fbffff 8d85fcfbffff 50 89b5f4fbffff ffd7 }
            // n = 5, score = 300
            //   ffb5f8fbffff         | push                dword ptr [ebp - 0x408]
            //   8d85fcfbffff         | lea                 eax, [ebp - 0x404]
            //   50                   | push                eax
            //   89b5f4fbffff         | mov                 dword ptr [ebp - 0x40c], esi
            //   ffd7                 | call                edi

        $sequence_6 = { 8945fc 53 56 57 ff35???????? e8???????? 8b15???????? }
            // n = 7, score = 300
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   ff35????????         |                     
            //   e8????????           |                     
            //   8b15????????         |                     

        $sequence_7 = { ff7534 e8???????? 837d3810 8bf8 8b4524 }
            // n = 5, score = 300
            //   ff7534               | push                dword ptr [ebp + 0x34]
            //   e8????????           |                     
            //   837d3810             | cmp                 dword ptr [ebp + 0x38], 0x10
            //   8bf8                 | mov                 edi, eax
            //   8b4524               | mov                 eax, dword ptr [ebp + 0x24]

        $sequence_8 = { 8d5dd8 50 ff75d8 8bc6 e8???????? a1???????? }
            // n = 6, score = 300
            //   8d5dd8               | lea                 ebx, [ebp - 0x28]
            //   50                   | push                eax
            //   ff75d8               | push                dword ptr [ebp - 0x28]
            //   8bc6                 | mov                 eax, esi
            //   e8????????           |                     
            //   a1????????           |                     

        $sequence_9 = { 8b4110 3bc6 7302 8bf0 8bc6 }
            // n = 5, score = 300
            //   8b4110               | mov                 eax, dword ptr [ecx + 0x10]
            //   3bc6                 | cmp                 eax, esi
            //   7302                 | jae                 4
            //   8bf0                 | mov                 esi, eax
            //   8bc6                 | mov                 eax, esi

    condition:
        7 of them and filesize < 204800
}