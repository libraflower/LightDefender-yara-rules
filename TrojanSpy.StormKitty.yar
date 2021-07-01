rule TrojanSpy_StormKitty {
   meta:
      description = "TrojanSpy.StormKittyn"
      author = "LightDefender"
      date = "2021-07-01"
      hash1 = "6d8c5897e76486a83beeffde123ad696f8668323ba19caaaaf6ddb14997e9d4f"
   strings:
      $s1 = "https://github.com/LimerBoy/StormKitty" ascii
      $s2 = "PasswordsStoreDirectory"
   condition:
      uint16(0) == 0x5a4d and any of them
}
