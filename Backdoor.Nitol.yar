import "pe"

rule MAL_Nitol_Malware_Jan19_1 {
   meta:
      description = "Detects Nitol Malware"
      author = "Florian Roth"
      reference = "https://twitter.com/shotgunner101/status/1084602413691166721"
      date = "2019-01-14"
      hash1 = "fe65f6a79528802cb61effc064476f7b48233fb0f245ddb7de5b7cc8bb45362e"
   strings:
      $xc1 = { 00 25 75 20 25 73 00 00 00 30 2E 30 2E 30 2E 30
               00 25 75 20 4D 42 00 00 00 25 64 2A 25 75 25 73
               00 7E 4D 48 7A }
      $xc2 = "GET ^&&%$%$^" ascii

      $n1 = ".htmGET " ascii

      $s1 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.00; Windows NT %d.0; MyIE 3.01)" fullword ascii
      $s2 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.0; Windows NT %d.1; SV1)" fullword ascii
      $s3 = "User-Agent:Mozilla/5.0 (X11; U; Linux i686; en-US; re:1.4.0) Gecko/20080808 Firefox/%d.0" fullword ascii
      $s4 = "User-Agent:Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and (
         pe.imphash() == "286870a926664a5129b8b68ed0d4a8eb" or
         1 of ($x*) or
         #n1 > 4 or
         4 of them
      )
}

rule backdoor_nitol {
   meta:
      description = "Backdoor.Nitol"
      author = "LightDefender"
      date = "2021-06-13"
      hash1 = "6a06c1e234a840cc194eb17e7f102a63cecf72355d015af68d3c7af09e3d1729"
   strings:
      $s1 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.0; Windows NT %d.1; SV1)" fullword ascii
      $s2 = "360tray.exe" fullword ascii
      $s3 = "%c%c%c%c%c%c.exe" fullword ascii
      $s4 = "User-Agent:Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii
      $s5 = "ast.exe" fullword ascii
      $s6 = "AST.exe" fullword ascii
      $s7 = "GET %s%s HTTP/1.1" fullword ascii
      $s8 = "%d.exe" fullword ascii
      $s9 = "cmd /c %s" fullword ascii
      $s10 = "jdfwkey" fullword ascii
      $s11 = "TODO: layout dialog bar" fullword wide
      $s12 = "%s %s %s%d" fullword ascii
      $s13 = "gy.dat" fullword wide
      $s14 = "InitWSAStartup Error!" fullword ascii
      $s15 = "WSAStartup failed: %d" fullword ascii
      $s16 = "rolSet\\Services\\" fullword ascii
      $s17 = "Set IP_HDRINCL Error!" fullword ascii
      $s18 = "WSASocket() failed: %d" fullword ascii
      $s19 = "SYSTEM\\CurrentCont" fullword ascii
      $s20 = "192.168.1.32" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      5 of them
}

rule win_nitol_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-12-22"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nitol"
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
        $sequence_0 = { 8d85d4fbffff 68???????? 50 ff15???????? 6a31 }
            // n = 5, score = 200
            //   8d85d4fbffff         | lea                 eax, [ebp - 0x42c]
            //   68????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   6a31                 | push                0x31

        $sequence_1 = { ffd6 668945a6 8d85b0feffff 50 e8???????? 8065ed00 }
            // n = 6, score = 200
            //   ffd6                 | call                esi
            //   668945a6             | mov                 word ptr [ebp - 0x5a], ax
            //   8d85b0feffff         | lea                 eax, [ebp - 0x150]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8065ed00             | and                 byte ptr [ebp - 0x13], 0

        $sequence_2 = { 59 59 68???????? 6a00 57 ff35???????? }
            // n = 6, score = 200
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   68????????           |                     
            //   6a00                 | push                0
            //   57                   | push                edi
            //   ff35????????         |                     

        $sequence_3 = { 0f8459030000 6a61 5e a1???????? }
            // n = 4, score = 200
            //   0f8459030000         | je                  0x35f
            //   6a61                 | push                0x61
            //   5e                   | pop                 esi
            //   a1????????           |                     

        $sequence_4 = { 6a0a ffd7 ebb2 53 ff15???????? }
            // n = 5, score = 200
            //   6a0a                 | push                0xa
            //   ffd7                 | call                edi
            //   ebb2                 | jmp                 0xffffffb4
            //   53                   | push                ebx
            //   ff15????????         |                     

        $sequence_5 = { 50 55 ff742418 ffd3 }
            // n = 4, score = 200
            //   50                   | push                eax
            //   55                   | push                ebp
            //   ff742418             | push                dword ptr [esp + 0x18]
            //   ffd3                 | call                ebx

        $sequence_6 = { ff15???????? c3 b8???????? e8???????? 83ec10 56 6a03 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   c3                   | ret                 
            //   b8????????           |                     
            //   e8????????           |                     
            //   83ec10               | sub                 esp, 0x10
            //   56                   | push                esi
            //   6a03                 | push                3

        $sequence_7 = { 6a20 50 e8???????? 668945e8 8d45ec 53 50 }
            // n = 7, score = 200
            //   6a20                 | push                0x20
            //   50                   | push                eax
            //   e8????????           |                     
            //   668945e8             | mov                 word ptr [ebp - 0x18], ax
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   53                   | push                ebx
            //   50                   | push                eax

        $sequence_8 = { 89442424 ffd7 8b3d???????? 66896c2426 89442410 896c2434 8d442434 }
            // n = 7, score = 200
            //   89442424             | mov                 dword ptr [esp + 0x24], eax
            //   ffd7                 | call                edi
            //   8b3d????????         |                     
            //   66896c2426           | mov                 word ptr [esp + 0x26], bp
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   896c2434             | mov                 dword ptr [esp + 0x34], ebp
            //   8d442434             | lea                 eax, [esp + 0x34]

        $sequence_9 = { 50 8d8558ffffff 50 e8???????? 83c40c 6a05 6a1a }
            // n = 7, score = 200
            //   50                   | push                eax
            //   8d8558ffffff         | lea                 eax, [ebp - 0xa8]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a05                 | push                5
            //   6a1a                 | push                0x1a

    condition:
        7 of them and filesize < 139264
}
