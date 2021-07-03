rule Ransom_Huahitec {
   meta:
      description = "Ransom.Huahitec"
      author = "LightDefender"
      date = "2021-07-03"
      hash1 = "4852f22df095db43f2a92e99384ff7667020413e74f67fcbd42fca16f8f96f4c"
      hash2 = "714f630043670cdab4475971a255d836a1366e417cd0b60053bf026551d62409"
   strings:
      $a1 = "Huahitec.exe" fullword wide
      $a2 = "Selected compression algorithm is not supported." fullword wide
      $a3 = "<Encrypt2>b__3f" fullword ascii
      $b1 = "F935DC23-1CF0-11D0-ADB9-00C04FD58A0B" nocase ascii wide
      $b2 = "SimpleZip" fullword ascii
      $b3 = "CryptoStream" fullword ascii
      $s1 = "GetAesTransform" fullword ascii
      $s2 = "GetFromResource" fullword ascii
      $s3 = "CreateGetStringDelegate" fullword ascii
      $s4 = "<Encrypt2>b__40" fullword ascii
      $s5 = "Unknown Header" fullword wide
      $s6 = "SmartAssembly.Attributes" fullword ascii
      $s7 = "CompressionAlgorithm" fullword ascii
      $s8 = "hashtableLock" fullword ascii
      $s9 = "DoNotPruneAttribute" fullword ascii
      $s10 = "MemberRefsProxy" fullword ascii
      $s11 = "DoNotPruneTypeAttribute" fullword ascii
      $s12 = "SmartAssembly.Zip" fullword ascii
      $s13 = "Huahitec" fullword ascii
      $s14 = "GetCachedOrResource" fullword ascii
      $s15 = "<Killproc>b__5" fullword ascii
      $s16 = "<Killproc>b__4" fullword ascii
      $s17 = "PathLink" fullword ascii
      $x1 = "RijndaelManaged" fullword ascii
      $x2 = "Microsoft.VisualBasic" ascii
   condition:
      uint16(0) == 0x5a4d and 2 of ($a*) and 2 of ($b*) and 6 of ($s*) and all of ($x*)
}
