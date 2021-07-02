rule Adware_Gator {
   meta:
      description = "Adware.Gator"
      author = "LightDefender"
      date = "2021-07-02"
      hash1 = "968f0ae8656e4a53da28998da61bbbfe12a47ef708d309dddb8ccdd999914483"
   strings:
      $s1 = "trickle.gator.com" fullword ascii
      $s2 = "ArBase Test Bitmap Window" fullword ascii
   condition:
      uint16(0) == 0x5a4d and 2 of them
}
