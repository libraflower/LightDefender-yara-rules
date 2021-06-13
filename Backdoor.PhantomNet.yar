rule PhantomNet {
   meta:
      description = "PhantomNet"
      date = "2021-06-13"
      author = "LightDefender"
      hash1 = "603881f4c80e9910ab22f39717e8b296910bff08cd0f25f78d5bff1ae0dce5d7"
   strings:
      $s1 = {00 4D 52 47 4F 2E 64 6C 6C 00 45 6E 74 65 72 79 00}
   condition:
      uint16(0) == 0x5a4d and all of them
}
