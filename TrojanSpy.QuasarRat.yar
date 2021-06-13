rule spy_quasarrat {
   meta:
      description = "QuasarRat"
      author = "LightDefender"
      date = "2021-06-13"
      hash1 = "38038560199f5d1da23f83e933492a1f5e6c010b8289f6fdae2e1adbec839a12"
   strings:
      $x1 = "PGma.System.MouseKeyHook, Version=5.6.130.0, Culture=neutral, PublicKeyToken=null" fullword ascii
      $x2 = "DQuasar.Common, Version=1.4.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii
      $s3 = "Process already elevated." fullword wide
      $s4 = "get_PotentiallyVulnerablePasswords" fullword ascii
      $s5 = "GetKeyloggerLogsDirectoryResponse" fullword ascii
      $s6 = "System.Collections.Generic.IEnumerable<Gma.System.MouseKeyHook.KeyPressEventArgsExt>.GetEnumerator" fullword ascii
      $s7 = "System.Collections.Generic.IEnumerator<Quasar.Common.Models.FileChunk>.get_Current" fullword ascii
      $s8 = "GetKeyloggerLogsDirectory" fullword ascii
      $s9 = "System.Collections.Generic.IEnumerator<Gma.System.MouseKeyHook.KeyPressEventArgsExt>.get_Current" fullword ascii
      $s10 = "set_PotentiallyVulnerablePasswords" fullword ascii
      $s11 = "Oprotobuf-net, Version=2.4.0.0, Culture=neutral, PublicKeyToken=257b51d87d2e4d67" fullword ascii
      $s12 = "potentiallyVulnerablePasswords" fullword ascii
      $s13 = "<PotentiallyVulnerablePasswords>k__BackingField" fullword ascii
      $s14 = "=Client, Version=1.4.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii
      $s15 = "get_DismissedBreachAlertsByLoginGuid" fullword ascii
      $s16 = "GetProcessesResponse" fullword ascii
      $s17 = "BQuasar.Client.Extensions.RegistryKeyExtensions+<GetKeyValues>d__15" fullword ascii
      $s18 = "Opera Software\\Opera Stable\\Login Data" fullword wide
      $s19 = "https://tools.keycdn.com/geo.json" fullword wide
      $s20 = "Are you mixing protobuf-net and protobuf-csharp-port? See https://stackoverflow.com/q/11564914/23354; type: " fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule QuasarRat {
   meta:
      description = "QuasarRAT"
      author = "LightDefender"
      date = "2021-06-13"
      hash1 = "ac14bf805d1796f1463b5f27b79496dab9a07f5bd50336628bcfbdc2dc996acf"
      hash2 = "38038560199f5d1da23f83e933492a1f5e6c010b8289f6fdae2e1adbec839a12"
      hash3 = "ba1a9d2896a18d3f95fb6fb7f94be8adcc60f76a7b5bb8b3c9401c5c64842843"
   strings:
      $s1 = "encryptedUsername" fullword ascii
      $s2 = "hostname" fullword ascii /* Goodware String - occured 84 times */
      $s3 = "Internet Explorer" fullword wide /* Goodware String - occured 518 times */
      $s4 = "mozglue.dll" fullword wide /* Goodware String - occured 1 times */
      $s5 = "nss3.dll" fullword wide /* Goodware String - occured 4 times */
      $s6 = "encryptedPassword" fullword ascii /* Goodware String - occured 5 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
}
