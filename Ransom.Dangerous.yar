rule Ransom_Dangerous {
   meta:
      description = "Ransom.Dangerous"
      author = "LightDefender"
      date = "2021-06-30"
      hash1 = "cf25a92a1f137bda5fb517d656dd9759d32231ea65b5a4f36e24db28b6980af1"
   strings:
      $s1 = "DANGEROUS_RANSOM" fullword ascii
      $s2 = "C:\\Users\\%username%\\myscript.vbs" fullword ascii
      $s3 = "dir /b /s C:\\Users\\%username%\\Documents\\* >> C:\\Users\\%username%\\troll.txt" fullword ascii
   condition:
      uint16(0) == 0x5a4d and any of them
}
