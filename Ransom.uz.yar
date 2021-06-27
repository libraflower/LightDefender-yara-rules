rule Ransom_uz {
   meta:
      description = "Ransom.uz"
      author = "LightDefender"
      date = "2021-06-27"
      hash1 = "177d6fc932b61cea08b4f243548bfc6288c8485af48b13f9270e790691209542"
      hash2 = "51fb2e1003298cf34cbefc408888c4e1b6bae6ce344486242b959857e89a2753"
   strings:
      $s1 = "TimaiosShraga12@protonmail.com" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and all of them
}
