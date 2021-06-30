rule Ransom_NoCry {
   meta:
      description = "Ransom.NoCry"
      author = "LightDefender"
      date = "2021-06-30"
      hash1 = "486f2053c32ba44eb2afaf87e1ba8d8db408ef09cb7d895f3a8dc0f4081a7467"
   strings:
      $s1 = "https://www.google.com/search?q=how+to+buy+bitcoin"
      $s2 = "C:\\Users\\ku5h2\\OneDrive\\Desktop\\NoCry Discord\\ransomeware\\obj\\Debug\\NoCry.pdb"
      $s3 = " worth of bitcoin to this address:"
      $s4 = "Ooooops All Your Files Are Encrypted ,NoCry"
      $s5 = "NoCry.Form4.resources"
      $s6 = "Decryption : Working * "
      $s7 = "Runcount.cry"
      $op1 = {28 36 00 00 0A 00 1F FE 0A 18 0C 02 19 17 73 EE 00 00 0A 80 4E 00 00 04 19 0C 03 1A 18 73 EE 00 00 0A 80 4F 00 00}
   condition:
      uint16(0) == 0x5a4d and any of them
}
