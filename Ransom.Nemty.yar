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

rule nemty_ransomware {

   meta:

      description = "Rule to detect Nemty Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2020-02-23"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Nemty"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/nemty-ransomware-learning-by-doing/"
      hash = "73bf76533eb0bcc4afb5c72dcb8e7306471ae971212d05d0ff272f171b94b2d4"

   strings:

      $x1 = "/c vssadmin.exe delete shadows /all /quiet & bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default}" fullword ascii
      $s2 = "https://pbs.twimg.com/media/Dn4vwaRW0AY-tUu.jpg:large :D" fullword ascii
      $s3 = "MSDOS.SYS" fullword wide
      $s4 = "/c vssadmin.exe delete shadows /all /quiet & bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} " ascii
      $s5 = "recoveryenabled no & wbadmin delete catalog -quiet & wmic shadowcopy delete" fullword ascii
      $s6 = "DECRYPT.txt" fullword ascii
      $s7 = "pv3mi+NQplLqkkJpTNmji/M6mL4NGe5IHsRFJirV6HSyx8mC8goskf5lXH2d57vh52iqhhEc5maLcSrIKbukcnmUwym+In1OnvHp070=" fullword ascii
      $s8 = "\\NEMTY-DECRYPT.txt\"" fullword ascii
      $s9 = "rfyPvccxgVaLvW9OOY2J090Mq987N9lif/RoIDP89luS9Ouv9gUImpgCTVGWvJzrqiS8hQ5El02LdEvKcJ+7dn3DxiXSNG1PwLrY59KzGs/gUvXnYcmT6t34qfZmr8g8" ascii
      $s10 = "IO.SYS" fullword wide
      $s11 = "QgzjKXcD1Jh/cOLBh1OMb+rWxUbToys2ArG9laNWAWk0rNIv2dnIDpc+mSbp91E8qVN8Mv8K5jC3EBr4TB8jh5Ns/onBhPZ9rLXR7wIkaXGeTZi/4/XOtO3DFiad4+vf" ascii
      $s12 = "NEMTY-DECRYPT.txt" fullword wide
      $s13 = "pvXmjPQRoUmjj0g9QZ24wvEqyvcJVvFWXc0LL2XL5DWmz8me5wElh/48FHKcpbnq8C2kwQ==" fullword ascii
      $s14 = "a/QRAGlNLvqNuONkUWCQTNfoW45DFkZVjUPn0t3tJQnHWPhJR2HWttXqYpQQIMpn" fullword ascii
      $s15 = "KeoJrLFoTgXaTKTIr+v/ObwtC5BKtMitXq8aaDT8apz98QQvQgMbncLSJWJG+bHvaMhG" fullword ascii
      $s16 = "pu/hj6YerUnqlUM9A8i+i/UhnvsIE+9XTYs=" fullword ascii
      $s17 = "grQkLxaGvL0IBGGCRlJ8Q4qQP/midozZSBhFGEDpNElwvWXhba6kTH1LoX8VYNOCZTDzLe82kUD1TSAoZ/fz+8QN7pLqol5+f9QnCLB9QKOi0OmpIS1DLlngr9YH99vt" ascii
      $s18 = "BOOTSECT.BAK" fullword wide
      $s19 = "bbVU/9TycwPO+5MgkokSHkAbUSRTwcbYy5tmDXAU1lcF7d36BTpfvzaV5/VI6ARRt2ypsxHGlnOJQUTH6Ya//Eu0jPi/6s2MmOk67csw/msiaaxuHXDostsSCC+kolVX" ascii
      $s20 = "puh4wXjVYWJzFN6aIgnClL4W/1/5Eg6bm5uEv6Dru0pfOvhmbF1SY3zav4RQVQTYMfZxAsaBYfJ+Gx+6gDEmKggypl1VcVXWRbxAuDIXaByh9aP4B2QvhLnJxZLe+AG5" ascii

   condition:
   
      ( uint16(0) == 0x5a4d and
      filesize < 400KB and
      ( 1 of ($x*) and
      4 of them ))
}

rule nemty_ransomware_2_6 {

   meta:

      description = "Rule to detect Nemty Ransomware version 2.6"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2020-04-06"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Nemty"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/nemty-ransomware-learning-by-doing/"
      hash = "52b7d20d358d1774a360bb3897a889e14d416c3b2dff26156a506ff199c3388d"

   strings:

   	  /*
		BYTES:
		558BEC83EC245356578955F4294DF46A048D72038D79015A8BC78955DC8A5EFD8858FF8B5DF48A1C0388188A5EFF8858018A1E88580203F203C2FF4DDC75DE8955F48D51038D42108D59028945F8894DF0297DF0895DEC297DEC8955E8297DE88D470C8D7902894DE4297DE48955DC297DDC8B7DF8894DE02955E08D7102F645F4038B5DEC8A1C038B4DF08A14018A08885DFA8B5DE88A1C03885DFB753B0FB6DB8A9B281241000FB6C98855FF8A91281241000FB64DFA8A8928124100885DFA0FB65DFF8A9B28124100885DFB8B5DF4C1EB023293281441008B5DE48A1C3332DA8B55E0881C178A50F432D18850048A0E324DFA83C004884E108B4DDC8A0C31324DFBFF45F4880F83C60483C704837DF42C0F8266FFFFFF5F5E5BC9C3558BEC560FB6C057C1E0040345086A045F6A045E8A10301140414E75F74F75F15F5E5DC356576A045F6A048BC15E0FB6108A9228124100881083C0044E75EF414F75E65F5EC38A50058A48018850018A50098850058A500D8850098A500A88480D8A48028850028A500E88480A8A48068850068A500F88480E8A48038850038A500B88500F8A500788500B884807C3558BEC5153566A0483C1025E8A410132018A51FE8A59FF8845FD32C232C38845FF8855FE32D38AC2C0E807B31BF6EB02D232C23245FE8A51FF3245FF32118841FE8AC2C0E807F6EB02D232C23241FF8A55FD3245FF8841FF8AC2C0E807F6EB02D232C232018A51013245FF3255FE88018AC2C0E807F6EB02D232C232410183C1043245FF4E8841FD75825E5BC9C3558BEC53FF75088BCE32C0E8D3FEFFFF59B3018BCEE8EDFEFFFF8BC6E808FFFFFF8BCEE84AFFFFFFFF75088BCE8AC3E8AFFEFFFFFEC35980FB0A72D78BCEE8C4FEFFFF8BC6E8DFFEFFFF5B8BCEB00A5DE98EFEFFFF558BEC81ECC8000000A18440410033C58945FC8B4508578D8D3CFFFFFF898538FFFFFFE849FDFFFF33FF6A1058397D0C764F5683F8107534508D45EC5350E88E6000008D853CFFFFFF508D75ECE859FFFFFF83C4106A0F58803C03FF7509C60403004879F3EB03FE041833C08A4C05EC8BB538FFFFFF300C3E47403B7D0C72B35E8B4DFC33CD5FE835600000C9C3558BEC51515333C05633F632DB8945FC39450C0F8682000000578B7DFC8B55088A14178BFE83EF0074504F74374F755D217DF80FB6FB0FB6F283E70F8BDEC1EB06C1E7020BFB8A9F6811410083E63F881C088A9E681141008B75F8885C080183C002EB290FB6FB0FB6DA83E7036A02C1E704C1EB045E0BFBEB0933F60FB6FA46C1EF028A9F68114100881C0840FF45FC8ADA8B55FC3B550C72805F4E741D4E75360FB6D383E20F8A149568114100881408C64408013D83C002EB1C0FB6D383E203C1E2048A926811410088140866C74408013D3D83C0035EC60408005BC9C3558BEC33C0F6450C0375775733FF39450C766E8B4D088A0C0F80F93D746380F92B7C5C80F97A7F570FB6C98A89A811410080F9FF74498BD783E20383EA0074314A741D4A74094A752E080C3040EB288AD1C0EA0280E20F08143040C0E106EB148AD1C0EA0480E20308143040C0E104EB03C0E102880C30473B7D0C7296EB0233C05F5DC3558BEC518B0B85C974298B4304568BF18945FC3BF07413576A0133FFE81E00000083C61C3B75FC75EF5FFF33E84A630000595E33C08903894304894308C9C3558BEC807D08007420837E1410721A538B1E85FF740B575356E8835E000083C40C53E815630000595BC746140F000000897E10C60437005DC20400C701C0F24000E9E5630000558BEC568BF1C706C0F24000E8D4630000F6450801740756E8D9620000598BC65E5DC20400558BEC83E4F881ECEC020000A18440410033C4898424E80200005356578D4508508D742450E89915000068341441008D842488000000E8AE1500006A075F33C083EC1C668944244C8D45088BF433DB50897C2464895C2460E866150000E8CC0E000033C066894424308B8424B00000000344247883C41C8D4C2414897C2428895C2424E8BA1E0000538D4424505083C8FF8D74241CE8D8200000538D8424880000005083C8FFE8C72000008BDE8D442430E8A61500006A0133FFE87F160000837C2444088B44243073048D4424308D8C24A00000005150FF15DCF040008944241083F8FF0F842E0500008B3598F04000683C1441008D8424D000000050FFD685C00F84ED04000068401441008D8424D000000050FFD685C00F84D604000068481441008D8424D000000050FFD685C00F84BF04000068501441008D8424D000000050FFD685C00F84A804000068601441008D8424D000000050FFD685C00F8491040000687C1441008D8424D000000050FFD685C00F847A04000068841441008D8424D000000050FFD685C00F846304000068A01441008D8424D000000050FFD685C00F844C04000068AC1441008D8424D000000050FFD685C00F843504000068C01441008D8424D000000050FFD685C00F841E04000068D01441008D8424D000000050FFD685C00F840704000068E41441008D8424D000000050FFD685C00F84F003000068001541008D8424D000000050FFD685C00F84D903000068181541008D8424D000000050FFD685C00F84C203000068301541008D8424D000000050FFD685C00F84AB03000068481541008D8424D000000050FFD685C00F8494030000685C1541008D8424D000000050FFD685C00F847D03000068781541008D8424D000000050FFD685C00F846603000068881541008D8424D000000050FFD685C00F844F03000068A01541008D8424D000000050FFD685C00F843803000068B01541008D8424D000000050FFD685C00F842103000068CC1541008D8424D000000050FFD685C00F840A03000068F41541008D8424D000000050FFD685C00F84F302000068081641008D8424D000000050FFD685C00F84DC020000F68424A0000000108D8424CC000000508D4C246C8D4424507450E8441A0000598D4C241451E88F1A00008BD8598D442430E80E1300006A0133FF8D742418E8E31300006A018D74246CE8D813000083EC1C8D44244C8BF450E84E120000E886FCFFFF83C41CE972020000E8F41900008BD8598D442430E8C91200006A0133FF8D74246CE89E1300008D8424CC00000050FF15ACF14000508D442418E8311200008B4424146A085F397C242873048D4424148B3598F04000681816410050FFD685C00F84080200008B442414397C242873048D442414682416410050FFD685C00F84EA0100008B442414397C242873048D442414683016410050FFD685C00F84CC0100008B442414397C242873048D442414683C16410050FFD685C00F84AE0100008B442414397C242873048D442414684816410050FFD685C00F84900100008B442414397C242873048D442414685416410050FFD685C00F84720100008B442414397C242873048D442414686016410050FFD685C00F84540100008B442414397C242873048D442414686C16410050FFD685C00F84360100008B442414397C242873048D442414687816410050FFD685C00F84180100008B442414397C242873048D442414688416410050FFD685C00F84FA0000008B442414397C242873048D442414689016410050FFD685C00F84DC0000008B442414397C242873048D442414689C16410050FFD685C00F84BE0000008B442414397C242873048D44241468A816410050FFD685C00F84A00000008B442414397C242873048D44241468B416410050FFD685C00F84820000008B442414397C242873048D44241468C816410050FFD685C074688B442414397C242873048D44241468D416410050FFD685C0744E83EC1C8BC468E0164100E84110000083EC1C8D8C24040100008BC451E82F100000E83456000083C43885C075218B4C2430397C244473048D4C243083EC1C8BC451E80A100000E8CE0A000083C41C6A0133FF8D742418E84A1100008D8424A000000050FF742414FF1594F0400085C00F85DCFAFFFFFF742410FF15A0F0400033DB435333FF8D742434
		*/
         
      $pattern = { 558B??83????53565789????29????6A??8D????8D????5A8B??89????8A????88????8B????8A????88??8A????88????8A??88????03??03??FF????75??89????8D????8D????8D????89????89????29????89????29????89????29????8D????8D????89????29????89????29????8B????89????29????8D????F6??????8B????8A????8B????8A????8A??88????8B????8A????88????75??0FB6??8A??????????0FB6??88????8A??????????0FB6????8A??????????88????0FB6????8A??????????88????8B????C1????32??????????8B????8A????32??8B????88????8A????32??88????8A??32????83????88????8B????8A????32????FF????88??83????83????83??????0F82????????5F5E5BC9C3558B??560FB6??57C1????03????6A??5F6A??5E8A??30??40414E75??4F75??5F5E5DC356576A??5F6A??8B??5E0FB6??8A??????????88??83????4E75??414F75??5F5EC38A????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????88????C3558B??5153566A??83????5E8A????32??8A????8A????88????32??32??88????88????32??8A??C0????B3??F6??02??32??32????8A????32????32??88????8A??C0????F6??02??32??32????8A????32????88????8A??C0????F6??02??32??32??8A????32????32????88??8A??C0????F6??02??32??32????83????32????4E88????75??5E5BC9C3558B??53FF????8B??32??E8????????59B3??8B??E8????????8B??E8????????8B??E8????????FF????8B??8A??E8????????FE??5980????72??8B??E8????????8B??E8????????5B8B??B0??5DE9????????558B??81??????????A1????????33??89????8B????578D??????????89??????????E8????????33??6A??5839????76??5683????75??508D????5350E8????????8D??????????508D????E8????????83????6A??5880??????75??C6??????4879??EB??FE????33??8A??????8B??????????30????47403B????72??5E8B????33??5FE8????????C9C3558B??51515333??5633??32??89????39????0F86????????578B????8B????8A????8B??83????74??4F74??4F75??21????0FB6??0FB6??83????8B??C1????C1????0B??8A??????????83????88????8A??????????8B????88??????83????EB??0FB6??0FB6??83????6A??C1????C1????5E0B??EB??33??0FB6??46C1????8A??????????88????40FF????8A??8B????3B????72??5F4E74??4E75??0FB6??83????8A????????????88????C6????????83????EB??0FB6??83????C1????8A??????????88????66????????????83????5EC6??????5BC9C3558B??33??F6??????75??5733??39????76??8B????8A????80????74??80????7C??80????7F??0FB6??8A??????????80????74??8B??83????83????74??4A74??4A74??4A75??08????40EB??8A??C0????80????08????40C0????EB??8A??C0????80????08????40C0????EB??C0????88????473B????72??EB??33??5F5DC3558B??518B??85??74??8B????568B??89????3B??74??576A??33??E8????????83????3B????75??5FFF??E8????????595E33??89??89????89????C9C3558B??80??????74??83??????72??538B??85??74??575356E8????????83????53E8????????595BC7????????????89????C6??????5DC2????C7??????????E9????????558B??568B??C7??????????E8????????F6??????74??56E8????????598B??5E5DC2????558B??83????81??????????A1????????33??89????????????5356578D????508D??????E8????????68????????8D????????????E8????????6A??5F33??83????66????????8D????8B??33??5089??????89??????E8????????E8????????33??66????????8B????????????03??????83????8D??????89??????89??????E8????????538D??????5083????8D??????E8????????538D????????????5083????E8????????8B??8D??????E8????????6A??33??E8????????83????????8B??????73??8D??????8D????????????5150FF??????????89??????83????0F84????????8B??????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????F6??????????????8D????????????508D??????8D??????74??E8????????598D??????51E8????????8B??598D??????E8????????6A??33??8D??????E8????????6A??8D??????E8????????83????8D??????8B??50E8????????E8????????83????E9????????E8????????8B??598D??????E8????????6A??33??8D??????E8????????8D????????????50FF??????????508D??????E8????????8B??????6A??5F39??????73??8D??????8B??????????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??74??8B??????39??????73??8D??????68????????50FF??85??74??83????8B??68????????E8????????83????8D????????????8B??51E8????????E8????????83????85??75??8B??????39??????73??8D??????83????8B??51E8????????E8????????83????6A??33??8D??????E8????????8D????????????50FF??????FF??????????85??0F85????????FF??????FF??????????33??435333??8D?????? }


   condition:
   
      uint16(0) == 0x5a4d and
      filesize < 1500KB and
      $pattern
}

rule MANSORY_ransomware {
   meta:
      description = "Rule to detect Mansory Ransomware"
      author = "LightDefender"
      date = "2021-6-18"

   strings:
      $s1 = "main.CTREncrypt" fullword ascii
      $s2 = "main.GenerateRandomBytes" fullword ascii
      $s3 = "idle: .MANSORY" ascii

   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and 2 of them
}
