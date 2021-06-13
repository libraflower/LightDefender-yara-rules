rule Ransom_Lucky {
   meta:
      description = "Lucky Ransomware"
      author = "LightDefender"
      date = "2021-06-13"
      hash1 = "5606e9dc4ab113749953687adac6ddb7b19c864f6431bdcf0c5b0e2a98cca39e"
      hash2 = "8ff979f23f8bab94ce767d4760811bde66c556c0c56b72bb839d4d277b3703ad"
   strings:
      $s1 = "gefas.pdb" fullword ascii
      $s2 = "ggqfslmb" fullword ascii
      $s4 = "gr7shadtasghdj" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 2 of them
}
