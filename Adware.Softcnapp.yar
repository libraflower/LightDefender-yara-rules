rule Adware_Softcnapp {
   meta:
      description = "Adware.Softcnapp"
      author = "LightDefender"
      date = "2021-08-02"
      hash1 = "01567b9763db0e7e38d681a5c346985e45a7e075d2a7edd84b431c461565f821"
      hash2 = "7c12c51bb4253b957647a4a71c3ab99e25b220a4813708724efd89960a581fd8"
      hash3 = "ee149fac6ca98c043f204fed8d946b32f0b5d736660bad134f171b2ed8a83520"
      hash4 = "7aba2c0649ac5e206d98f0ae510a42de69ef5361111d3bee532be37e820a7222"
      hash5 = "9e48d2ce8ec2c8832e84c3f54ec131c8d8edd83e4947d6e2d829f05b00ef9171"
   strings:
      $s1 = "TaskStart" fullword ascii
      $s2 = "TaskFree" fullword ascii
      $s3 = "OneTimes" fullword wide
      $s4 = "RunBus" fullword wide
      $s5 = "RunPath" fullword wide
      $s6 = "MinVer" fullword wide
      $s7 = "MaxVer" fullword wide
   condition:
      uint16(0) == 0x5a4d and all of them
}
