rule EICAR_TEST_FILE {
   meta:
      description = "Test.EICAR"
      author = "LightDefender"
      date = "2021-07-29"
      hash1 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
   strings:
      $s1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
   condition:
      all of them
}
rule HUORONG_TEST_FILE {
   meta:
      description = "Test.Huorong"
      author = "LightDefender"
      date = "2021-07-29"
      hash1 = "32f377d33406e016015f89d074c8a38ed186939192293b1f74698f296696d24c"
   strings:
      $s1 = "HUORONG ANTIVIRUS ENGINE TEST FILE"
   condition:
      uint16(0) == 0x5a4d and all of them
}
