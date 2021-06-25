rule Ransom_MBRLocker {
   meta:
      description = "Ransom.MBRLocker"
      date = "2021-06-26"
      author = "LightDefender"
   strings:
      $s1 = "PhysicalDrive0" nocase
      $s2 = "note.txt" ascii
      $s3 = "Your disk have a lock!" nocase
      $s4 = "Please input the unlock password!" nocase
      $s5 = {5bc678014e0d80fd8d858fc731384f4dff01ff01ff01ff01ff01}
      $s6 = {5bc678014e0d53ef4ee54e3a7a7a7684}
   condition:
      uint16(0) == 0x5a4d and $s1 and 2 of them
}
