rule Ransomware.Globeimposter {
   meta:
      description = "Globeimposter Ransomware"
      author = "LightDefender"
      date = "2021-06-13"
      hash1 = "e478fe703e64b417ed40b35dc5063e78afc00b26b867b12e648efd94d8be59cc"
   strings:
      $s1 = "fistulization7.dll" fullword ascii
      $s2 = "Husmandsforeningen.exe" fullword wide
      $s3 = "GetPrintProcessorDirectoryA" fullword ascii
      $s4 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s5 = "AShell_NotifyIconA" fullword ascii
      $s6 = "EnumPortsA" fullword ascii
      $s7 = "Tittupping" fullword ascii
      $s8 = "Husmandsforeningen" fullword wide
      $s9 = "Slappendes" fullword ascii
      $s10 = "Cosmetics" fullword ascii
      $s11 = "Besindedes" fullword ascii
      $s12 = "Pimpstenens" fullword ascii
      $s13 = "Pneumatogenic" fullword ascii
      $s14 = "Epimorphosis8" fullword ascii
      $s15 = "Antistimulation4" fullword ascii
      $s16 = "Crithidia3" fullword ascii
      $s17 = "Teksthenvisningen5" fullword ascii
      $s18 = "Unpuddled7" fullword ascii
      $s19 = "Underfakturerings6" fullword ascii
      $s20 = "UY3 /i" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}
