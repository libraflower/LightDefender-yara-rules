rule Virus_Neshta {
   meta:
      description = "Virus.Neshta"
      author = "LightDefender"
      date = "2021-08-04"
      hash1 = "58f33976b1934ff2e471844d7a7ee4c6e4ab3edb8ca2a6b88c86795c3368cfeb"
      hash2 = "a0baff0515a6ff0a42b19248dd7823063a25118963fc396c25f5e5cd6af3d59e"
      hash3 = "a95037039a9920384aa6b478ca54c7d839c72b203c5331a7ffbd9e0f9731c3dc"
   strings:
      $s1 = "Delphi-the best. Fuck off all the rest. Neshta 1.0 Made in Belarus. " fullword ascii
      $s2 = "! Best regards 2 Tommy Salo. [Nov-2005] yours [Dziadulja Apanas]" fullword ascii
   condition:
      uint16(0) == 0x5a4d and any of them
}
