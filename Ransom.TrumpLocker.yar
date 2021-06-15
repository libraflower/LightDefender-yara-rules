rule Ransomware_TrumpLocker {
   meta:
      description = "TrumpLocker Ransomware"
      author = "LightDefender"
      date = "2021-06-15"
   strings:
      $s1 = {54 00 68 00 65 00 54 00 72 00 75 00 6D 00 70 00 4C 00 6F 00 63 00 6B 00 65 00 72 00 2E 00 52 00 65 00 73 00 6F 00 75 00 72 00 63 00 65 00 73}
      $s2 = {6F 00 70 00 00 00 2E 00 75 00 73 00 61 00 00 00 2E 00 75 00 73 00 78 00 00 00 2E 00 75 00 74 00 32 00 00 00 2E 00 75 00 74 00 33 00 00 00 2E 00 75 00 74 00 63 00 00 00 2E 00 75 00 74 00 78 00 00 00 2E 00 75 00 76 00 78 00 00 00 2E 00 75 00 78 00 78 00 00 00 2E 00 76 00 6D 00 66}
      $s3 = {23 00 00 00 5C 00 57 00 68 00 61 00 74 00 20 00 68 00 61 00 70 00 70 00 65 00 6E 00 20 00 74 00 6F 00 20 00 6D 00 79 00 20 00 66 00 69 00 6C 00 65 00 73 00 2E 00 74 00 78 00 74 00 00 00 5C 00}
      $s4 = {52 00 61 00 6E 00 73 00 6F 00 6D 00 4E 00 6F 00 74 00 65 00 2E 00 65 00 78 00 65 00 00 00 5C 00}
      $s5 = {20 E7 01 00 00 72 D9 06 00 70 A2 06 20 E8 01 00 00 72 41 18 00 70 A2 06 20 E9 01 00 00 72 4B 18 00 70 A2 06 20 EA 01 00 00 72 57 18 00 70 A2 06}
      $s6 = {20 EB 01 00 00 72 61 18 00 70 A2 06 20 EC 01 00 00 72 6D 18 00 70 A2 06 20 ED 01 00 00 72 79 18 00 70 A2 06 20 EE 01 00 00 72 83 18 00 70 A2 06}
      $s7 = {0A 0A 06 72 E9 19 00 70 09 28 3A 00 00 0A 6F 43}
      $s8 = {72 13 1B 00 70 28 40 00 00 0A 72 27 1B 00 70 28 41 00 00 0A}
      $s9 = {6D 00 70 00 00 00 33 00 36 00 30 00 00 00 41 00}
      $s10 = {72 00 00 00 4B 00 61 00 73 00 70 00 65 00 72 00 73 00 6B 00 79 00 20 00 4C 00 61 00 62 00 00 00}
      $s11 = {6C 00 61 00 6D 00 00 00 2E 00 78 00 6C 00 6C 00}
      $s12 = {14 0B 1E 8D 3E 00 00 01 13 07 11 07 16 17 9C 11 07 17 18 9C 11 07 18 19 9C 11 07 19 1A 9C 11 07 1A 1B 9C 11 07 1B 1C 9C 11 07 1C 1D 9C 11 07 1D}
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      any of them
}