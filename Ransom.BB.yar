import "pe"
rule BB_Ransomware {
   meta:
      description = "BB Ransomware"
      date = "2021-06-15"
      author = "LightDefender"
      hash1 = "dee28396d1ec3e91bad9b0cb0b945a5512a70882bffbb1f47e153b27b41977df"
   strings:
      $s1 = "C:\\Users\\Remik Administrator\\source\\repos\\BB ransomware\\BB ransomware\\obj\\Debug\\BB ransomware.pdb" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and (all of them) and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744"
}
