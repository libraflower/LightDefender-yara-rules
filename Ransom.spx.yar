rule Ransom_spx {
   meta:
      description = "Ransom.spx"
      author = "LightDefender"
      date = "2021-07-01"
   strings:
      $s1 = {C7 EB CA E4 C8 EB BD E2 C3 DC CA DA C8 A8 C2 EB 00}
      $s2 = "pptxspx" fullword ascii
      $decrypt_key = "89213409" fullword ascii
   condition:
      uint16(0) == 0x5a4d and all of them
 }
 
 rule Ransom_spx_opcodes {
   meta:
      description = "Ransom.spx"
      author = "LightDefender"
      date = "2021-07-01"
   strings:
      $s1 = {558BEC83EC0C8D4DF4E8D2FFFFFF68085D40008D}
      $s2 = {8B450883C00450FF15AC50400083C4088BC65E5D}
      $s3 = {558BEC6AFF68B347400064A1000000005081EC58}
      $s4 = {558BEC516A08E82F0000008945FC5985C074108B}
      $s5 = {CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC8D4104C701}
   condition:
      uint16(0) == 0x5a4d and all of them
 }
