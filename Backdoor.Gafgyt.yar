rule Gafgyt_July_1 {
   meta:
      description = "Backdoor.Gafgyt"
      author = "LightDefender"
      date = "2021-07-01"
      hash1 = "041db2cf6eac2a47ae4651751158838104e502ff33dcc7f5dd48472789870e6c"
      hash2 = "0839b33e2da179eac610673769e9568d1942877739cf4d990f3787672a4e9af1"
      hash3 = "2a1c1a22ed6989e9ba86f9a192834e0a35afec8026e8ecc0bb5c958d2892d46c"
      hash4 = "30b682ee7114bf68f881e641e9ab14c7d62c84f725e9cf5bfccb403aaa1fe8f7"
      hash5 = "3b9a35f7a0698b24d214818efd22235c995f1460fc55dd3ebd923ff0dca5370c"
      hash6 = "4110dd04db3932f1f03bdce6fa74f5298ffb429b816c7a8fce40f1cbb043e968"
      hash7 = "471b4d64420bdf2c8749c390a142ed449aff23b0d67609b268be044657501fa7"
      hash8 = "5a9f02031f0b3b1a2edaeae2d77b8c1f67de2b611449432c42c88f840d7a1d5c"
      hash9 = "78d9488d688f3b12181b54df0e9da3770e90a4a42a13db001fd211d16645a1bb"
      hash10 = "7f2aa6e5e1f1229fb18a15d1599a7a6014796cc7c08b26b9c4336a2048dc8928"
      hash11 = "805917658c7761debdaf18e83b54ec4e9ba645950c773ddd21d6cd8ba29b32d6"
      hash12 = "ae880c7dd79ebb1d626aea57152fdaa779d07d5b326d7f7fad1d42b637e5da84"
      hash13 = "b0d36c18bf900988d01828202ce1ab77949b9a8a29b264ea1639f170a6c9825b"
      hash14 = "c17bf892498ed1dce5db1b0f3d588774b8e82f2636f397b2456d15e7442781e6"
      hash15 = "c27e328d2fe6fd75066938f58c3359c5dbb9deea166c6a4d3b0397d295a3e8d5"
      hash16 = "df292a289d93136fbdd6ac0850b2c8845f967d9a9a3bd29a9386b39843b82eda"
      hash17 = "e07a008aaf0a0a2666a705a9756da5bc54be18e2a53a50eb7539f1143548a57f"
      hash18 = "0be1e96f318d98398861217a9754bc003e6861d84de8553cdbd87531db66e19b"
      hash19 = "2d049876c256e55ae48a1060c32f8d75b691525cd877556172f163fe39466001"
      hash20 = "3d8194b7853a1edbaa5d14b4b7a0323c5584b8a5c959efe830073e43d0b4418a"
      hash21 = "576bce5c1d1143b0e532333a28d37c98d65b271d651dbce86360d3e80460733f"
      hash22 = "b7c5895189c7f4e30984e2f0db703c2120909dccaa339e59795d3e732bca9340"
      hash23 = "db23bf90a7f0c69c3501876243ca2fe29e9208864dfa6f2b5d0dac51061a3d86"
      hash24 = "e1093d59bef8f260b0ca1ebe82c0635cc225e060b8d7296efe330ca7837e6d44"
      hash25 = "e29d1c2cbd64d0f1433602f2b63cf40e33b4376ac613e911a2160b268496164d"
      hash26 = "e6523f691d0b4a16cc1892ec4eb3ee113d62443317e337412b70e0cea3e106f7"
      hash27 = "ec9387b582e5a935094c6d165741d2c989e72afc3c6063a29e96153e97a74af3"
      hash28 = "ed2eaf4c44f83c7920b2d73cbe242b82cc92e3188d04b1bb8742783c49487da7"
   strings:
      $s1 = "/20x/x58/x4b/x49/x57/x44/x49/x4a/x22/x20/x22/x64/x39/x63/x39/x29/x4d/x20/x29/x57/x5f/x22/x21/x5f/x2b/x20/x51/x53/x4d/x45/x4d/x44" ascii
      $s2 = "/73x/6ax/x4a/x4b/x4d/x44/x20/x44/x57/x29/x5f/x20/x44/x57/x49/x4f/x57/x20/x57/x4f/x4b/x3c/x20/x57/x44/x4b/x20/x44/x29/x5f/x41/" fullword ascii
      $s3 = "/20x/x58/x4b/x49/x57/x44/x49/x4a/x22/x20/x22/x64/x39/x63/x39/x29/x4d/x20/x29/x57/x5f/x22/x21/x5f/x2b/x20/x51/x53/x4d/x45/x4d/x44" ascii
      $s4 = "/x4d/x20/x29/x28/x28/x22/x29/x45/x4f/x4b/x58/x50/x7b/x20/x5f/x57/x44/x44/x57/x44/" fullword ascii
      $s5 = "/x71/x3b/x38/x38/x20/x43/x57/x29/x57/x22/x29/x64/x32/x20/x4b/x58/x4b/x4b/x4c/x22/x44/x20/x2d/x44/x5f/" fullword ascii
      $s6 = "UDPBYPASS" fullword ascii
      $s7 = "Is a named type file" fullword ascii
      $s8 = "Structure needs cleaning" fullword ascii
      $s9 = "No XENIX semaphores available" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 600KB and 5 of them
}

rule Gafgyt_July_6 {
   meta:
      description = "Backdoor.Gafgyt"
      author = "LightDefender"
      date = "2021-07-06"
      hash1 = "821d34f7978fc65fe3b570e86cce45edc921a6cbf02b127fb1263a8448a1f62a"
   strings:
      $s1 = "infected.log" fullword ascii
      $s2 = "Samael-DDoS-Attack" fullword ascii
      $s3 = "B0TK1LL" fullword ascii
      $s4 = "This Device Has Been Infected by Samael Botnet Made By ur0a :)" ascii
   condition:
      uint16(0) == 0x457f and filesize < 600KB and 2 of them
}

rule elf_bashlite_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-06-10"
        version = "1"
        description = "Detects elf.bashlite."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.bashlite"
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
        $sequence_0 = { 21d0 3345fc c9 c3 55 }
            // n = 5, score = 300
            //   21d0                 | mov                 dword ptr [ebp - 4], 0
            //   3345fc               | mov                 edi, 0x512c00
            //   c9                   | inc                 esp
            //   c3                   | mov                 edi, esp
            //   55                   | mov                 edi, 0x512c00

        $sequence_1 = { e8???????? 89c2 89d0 c1e81f }
            // n = 4, score = 300
            //   e8????????           |                     
            //   89c2                 | mov                 byte ptr [ebx], 0
            //   89d0                 | sub                 eax, edx
            //   c1e81f               | cmp                 eax, dword ptr [esp + 0x7c]

        $sequence_2 = { e8???????? 8945ec 837dec00 750b 8b45ec }
            // n = 5, score = 300
            //   e8????????           |                     
            //   8945ec               | je                  0xffffff7c
            //   837dec00             | mov                 al, byte ptr [ebp - 0xf]
            //   750b                 | cmp                 al, 0xc0
            //   8b45ec               | mov                 al, byte ptr [ebp - 0xd]

        $sequence_3 = { f7d0 21d0 3345fc c9 }
            // n = 4, score = 300
            //   f7d0                 | mov                 ecx, eax
            //   21d0                 | dec                 eax
            //   3345fc               | mov                 edx, dword ptr [ebp - 0x40]
            //   c9                   | mov                 edi, 0x800

        $sequence_4 = { 750c e8???????? 8b00 83f804 }
            // n = 4, score = 300
            //   750c                 | cmp                 al, 0xfc
            //   e8????????           |                     
            //   8b00                 | jne                 0x18a
            //   83f804               | dec                 eax

        $sequence_5 = { eb0a c785ecefffff00000000 8b85ecefffff c9 c3 }
            // n = 5, score = 300
            //   eb0a                 | mov                 eax, dword ptr [eax]
            //   c785ecefffff00000000     | mov    dword ptr [ebp - 0x108], eax
            //   8b85ecefffff         | mov                 dword ptr [ebp - 0x10c], 0x8056e9e
            //   c9                   | mov                 dword ptr [ebp - 0x110], 5
            //   c3                   | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_6 = { 8b85ecefffff c9 c3 55 }
            // n = 4, score = 300
            //   8b85ecefffff         | add                 eax, 0x41
            //   c9                   | mov                 byte ptr [ebx], al
            //   c3                   | mov                 dword ptr [ebp - 0x1c], edx
            //   55                   | mov                 eax, dword ptr [ebp - 0x20]

        $sequence_7 = { c1f802 89c2 89d0 01c0 01d0 }
            // n = 5, score = 300
            //   c1f802               | mov                 dword ptr [ebp - 0x88], eax
            //   89c2                 | jmp                 0x159
            //   89d0                 | mov                 dword ptr [esp], eax
            //   01c0                 | mov                 ecx, eax
            //   01d0                 | or                  ecx, 0x800

        $sequence_8 = { 85c0 750c c785ecefffff01000000 eb0a c785ecefffff00000000 8b85ecefffff }
            // n = 6, score = 300
            //   85c0                 | mov                 dword ptr [ebp - 0x4c], edx
            //   750c                 | dec                 eax
            //   c785ecefffff01000000     | mov    edi, dword ptr [ebp - 0x18]
            //   eb0a                 | mov                 ecx, dword ptr [ebp - 0x38]
            //   c785ecefffff00000000     | mov    edx, dword ptr [ebp - 0x3c]
            //   8b85ecefffff         | add                 dword ptr [ebp - 0x34], eax

        $sequence_9 = { 21d0 3345fc c9 c3 }
            // n = 4, score = 300
            //   21d0                 | mov                 eax, dword ptr [ebp - 0x1c]
            //   3345fc               | mov                 word ptr [eax + 0xa], dx
            //   c9                   | mov                 dword ptr [esp], 0
            //   c3                   | movzx               edx, ax

    condition:
        7 of them and filesize < 274018
}
