rule Ransom_BlackMatter {
   meta:
      description = "Ransom.BlackMatter (a variant of Ransom.DarkSide)"
      author = "LightDefender"
      date = "2021-08-01"
   strings:
      $op1 = {558BEC81EC0401000053515256578DBDFCFEFFFF32C0AAB92A000000B0FFF3AAB03EAAB903000000B0FF}
      $op2 = {02C28B7D0CC1EB028D145B2BD052895DFC8B0E0FB6D10FB6DD578DBDFCFEFFFF}
   condition:
      uint16(0) == 0x5a4d and any of them
}
