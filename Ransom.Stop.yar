rule win_stop_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-12-22"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stop"
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
        $sequence_0 = { 6a12 ff33 ff15???????? 8b35???????? 8b3d???????? }
            // n = 5, score = 400
            //   6a12                 | push                0x12
            //   ff33                 | push                dword ptr [ebx]
            //   ff15????????         |                     
            //   8b35????????         |                     
            //   8b3d????????         |                     

        $sequence_1 = { 8d45e0 50 ffd6 85c0 75e2 6a64 ff15???????? }
            // n = 7, score = 400
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   75e2                 | jne                 0xffffffe4
            //   6a64                 | push                0x64
            //   ff15????????         |                     

        $sequence_2 = { 6a00 6a12 ff33 ff15???????? 8b35???????? 8b3d???????? }
            // n = 6, score = 400
            //   6a00                 | push                0
            //   6a12                 | push                0x12
            //   ff33                 | push                dword ptr [ebx]
            //   ff15????????         |                     
            //   8b35????????         |                     
            //   8b3d????????         |                     

        $sequence_3 = { 83c102 eb84 6a0c 68???????? e8???????? 8b7d08 }
            // n = 6, score = 400
            //   83c102               | add                 ecx, 2
            //   eb84                 | jmp                 0xffffff86
            //   6a0c                 | push                0xc
            //   68????????           |                     
            //   e8????????           |                     
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]

        $sequence_4 = { e8???????? 83c404 8b4b04 b8abaaaa2a 2b0b }
            // n = 5, score = 400
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b4b04               | mov                 ecx, dword ptr [ebx + 4]
            //   b8abaaaa2a           | mov                 eax, 0x2aaaaaab
            //   2b0b                 | sub                 ecx, dword ptr [ebx]

        $sequence_5 = { ffd6 85c0 75e8 6a0a ff7304 ff15???????? 3d02010000 }
            // n = 7, score = 400
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   75e8                 | jne                 0xffffffea
            //   6a0a                 | push                0xa
            //   ff7304               | push                dword ptr [ebx + 4]
            //   ff15????????         |                     
            //   3d02010000           | cmp                 eax, 0x102

        $sequence_6 = { e8???????? 83c404 33c0 c7463c07000000 c7463800000000 }
            // n = 5, score = 400
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   33c0                 | xor                 eax, eax
            //   c7463c07000000       | mov                 dword ptr [esi + 0x3c], 7
            //   c7463800000000       | mov                 dword ptr [esi + 0x38], 0

        $sequence_7 = { 56 6a00 ff7508 68???????? 6a00 6a00 ff15???????? }
            // n = 7, score = 400
            //   56                   | push                esi
            //   6a00                 | push                0
            //   ff7508               | push                dword ptr [ebp + 8]
            //   68????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_8 = { 51 51 dd1c24 e8???????? dc4de0 }
            // n = 5, score = 400
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   dd1c24               | fstp                qword ptr [esp]
            //   e8????????           |                     
            //   dc4de0               | fmul                qword ptr [ebp - 0x20]

        $sequence_9 = { ff7508 ffd0 5d c3 8b0d???????? 33d2 85c9 }
            // n = 7, score = 400
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ffd0                 | call                eax
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b0d????????         |                     
            //   33d2                 | xor                 edx, edx
            //   85c9                 | test                ecx, ecx

    condition:
        7 of them and filesize < 6029312
}

rule MALWARE_Win_STOP {
    meta:
        author = "ditekSHen"
        description = "Detects STOP ransomware"
        snort2_sid = "920113"
        snort3_sid = "920111"
        clamav_sig = "MALWARE.Win.Ransomware.STOP"
    strings:
        $x1 = "C:\\SystemID\\PersonalID.txt" fullword wide
        $x2 = "/deny *S-1-1-0:(OI)(CI)(DE,DC)" wide
        $x3 = "e:\\doc\\my work (c++)\\_git\\encryption\\" ascii wide nocase
        $s1 = "\" --AutoStart" fullword ascii wide
        $s2 = "--ForNetRes" fullword wide
        $s3 = "--Admin" fullword wide
        $s4 = "%username%" fullword wide
        $s5 = "?pid=" fullword wide
        $s6 = /&first=(true|false)/ fullword wide
        $s7 = "delself.bat" ascii
        $mutex1 = "{1D6FC66E-D1F3-422C-8A53-C0BBCF3D900D}" fullword ascii
        $mutex2 = "{FBB4BCC6-05C7-4ADD-B67B-A98A697323C1}" fullword ascii
        $mutex3 = "{36A698B9-D67C-4E07-BE82-0EC5B14B4DF5}" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((2 of ($x*) and 1 of ($mutex*)) or (all of ($x*)) or (6 of ($s*) and (1 of ($x*) or 1 of ($mutex*))) or (9 of them))
}

rule Ransom_Stop {
   meta:
      description = "Ransom.Stop"
      author = "LightDefender"
      date = "2021-06-27"
   strings:
      $s1 = "Zopeheci nol wubipanur vatesADiwidadepuzixem"
      $s2 = "%Tacexozemiyusij juxoyoyos jiwicefojulIHebecawadoxa"
      $s3 = "QWamem mutumog wenaze tayifetebuz yorelij ripif lezivemizan"
      $s4 = "vunafula.exe"
      $s5 = "zatir.exe"
      $s6 = "E:\\Doc\\My work (C++)\\_Git\\Encryption\\Release\\encrypt_win_api.pdb"
      $s7 = "SuspendYourMind" fullword ascii
      $s8 = "mowapevuvahoyobajimuluzo jojof xuvuxoyipunolakokedub hohivuligesohowu ferasorafawumahuzodisuley" fullword ascii
      $s9 = "fezekopupikayecicizojisowa zihebagaponaxo" fullword ascii
      $s10 = "C:\\pelocilixeru 8 ruxigofohege-noxi54\\bigi.pdb" fullword ascii
   condition:
      uint16(0) == 0x5a4d and any of them
}
