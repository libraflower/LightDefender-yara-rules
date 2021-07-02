rule Ransom_WannaCry {
   meta:
      description = "Ransom.WannaCry"
      author = "LightDefender"
      date = "2021-07-01"
      hash1 = "925b3acaa3252bf4d660eab22856fff155f3106c2fee7567711cb34374b499f3"
   strings:
      $s1 = "WNcry@2ol7" fullword ascii
      $s2 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii
      $s3 = "WanaCrypt0r" fullword ascii wide
      $op1 = {BE D8 F4 40 00 53 8D 85 F4 FD FF FF 56 50 FF 15 88 80 40 00 56 FF 15 68 80 40 00 83 F8 FF 74 0D}
   condition:
      uint16(0) == 0x5a4d and 3 of them
}

rule Ransom_WannaCry_Variant {
   meta:
      description = "Ransom.WannaCry"
      author = "LightDefender"
      date = "2021-07-01"
      hash1 = "925b3acaa3252bf4d660eab22856fff155f3106c2fee7567711cb34374b499f3"
   strings:
      $s1 = "Ooops, your files have been encrypted!"
      $s2 = "c:\\users\\amirlord\\documents\\visual studio 2017\\Projects\\WindowsFormsApp7\\WindowsFormsApp7\\obj\\Debug\\WannaCry.pdb" fullword ascii
   condition:
      uint16(0) == 0x5a4d and any of them
}

rule Ransom_WannaCry_Variant_June_30 {
   meta:
      description = "Ransom.WannaCry (FlyStudio)"
      author = "LightDefender"
      date = "2021-06-30"
      hash1 = "fa3ebf23620bbafc369a8af1d2a98eca52bf8b5e94707b17eb0771c2138d9250"
   strings:
      $s1 = {00 57 61 6E 6E 61 43 72 79 20 33 2E 30 20 20 40 50 6C 65 61 73 65 5F 52 65 61 64 5F 4D 65 40 00}
      $s2 = {C7 EB D6 A7 B8 B6 31 B8 F6 B1 C8 CC D8 B1 D2 B5 BD D5 E2 B5 D8 D6}
      $s3 = "dzclsh@gmail.com" ascii
      $s4 = {BD AB BD E2 C3 DC C4 FA B5 C4 CB F9 D3 D0 CE C4}
      $s5 = {D2 AA D6 D8 C3 FC C3 FB BC D3 C3 DC B5 C4 CE C4}
      $s6 = {00 00 43 68 65 63 6B 20 50 61 79 6D 65 6E 74 D0}
   condition:
      uint16(0) == 0x5a4d and any of ($s*)
}
