rule TrojanSpy_Vadokrist {
   meta:
      description = "TrojanSpy.Vadokrist"
      author = "LightDefender"
      date = "2021-08-01"
      hash1 = "dd25827dbcc8b9b95507b1cadf0647832050be8f441ebac958fd969c9e45a4bb"
      hash2 = "9cce1806299ad201adf1b0d6868fecbe61c4216ce14c23ce2ed0abbd15cb0d68"
      hash3 = "4f26922f13a2663ddd3ea216a8282c3ec230e08df9b83e957bb701b5ddfbdbff"
      hash4 = "db87fe194c98b4460518a9182d617843564da8df8467fa27887b9d47f8419485"
      hash5 = "83c5c159f0059d1d1d011e41a61cd2efb97a93ffefc6d0150b15c8d9981ed1bd"
   strings:
      $s1 = "C:\\WINDOWS\\system32\\shutdown.exe -r -t 1 -f" fullword ascii
      $s2 = "Msctf.dll" fullword wide
      $s3 = "core.exe" fullword wide
   condition:
      uint16(0) == 0x5a4d and all of them
}
