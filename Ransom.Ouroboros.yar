rule Ransom_Ouroboros {
   meta:
      description = "Ransom.Ouroboros"
      author = "LightDefender"
      date = "2021-06-30"
   strings:
      $a_op1 = {55 8B EC 6A FF 68 08 49 4F 00 64 A1 00 00 00 00 50 81 EC F8 01 00 00 A1 8C 51 53 00 33 C5 89 45 F0 53 56 57 50 8D 45 F4 64 A3 00 00 00 00 8B F1 89 B5 08 FE FF FF C7 45 FC 00 00 00 00 89 B5 FC}
      $a_op2 = {55 8D 6C 24 8C 83 EC 74 6A FF 68 D9 9B 4F 00 64 A1 00 00 00 00}
      $a_s1 = "C:\\ProgramData\\IDk.txt" fullword ascii
      $a_s2 = "C:\\ProgramData\\pkey.txt" fullword ascii
      $a_s3 = "Decrypt-info.txt" fullword
      $b_s1 = "sqlserver.exe" fullword ascii
      $b_s2 = "mysqld-opt.exe" fullword ascii
      $b_s3 = "threaad" fullword ascii
      $b_s4 = "DecodingLookupArray" fullword ascii
   condition:
      uint16(0) == 0x5a4d and (any of ($a*) or 3 of ($b*))
}
