rule Ransom_Huahitec {
   meta:
      description = "Ransom.Huahitec"
      author = "LightDefender"
      date = "2021-07-03"
      hash1 = "4852f22df095db43f2a92e99384ff7667020413e74f67fcbd42fca16f8f96f4c"
   strings:
      $a1 = "Huahitec.exe" fullword wide
      $a2 = "Selected compression algorithm is not supported." fullword wide
      $a3 = "<Encrypt2>b__3f" fullword ascii
      $x4 = "F935DC23-1CF0-11D0-ADB9-00C04FD58A0B" nocase ascii wide
      $s5 = "GetAesTransform" fullword ascii
      $s6 = "GetFromResource" fullword ascii
      $s7 = "CreateGetStringDelegate" fullword ascii
      $s8 = "<Encrypt2>b__40" fullword ascii
      $s9 = "Unknown Header" fullword wide
      $s10 = "SmartAssembly.Attributes" fullword ascii
      $s11 = "CompressionAlgorithm" fullword ascii
      $s12 = "hashtableLock" fullword ascii
      $s13 = "DoNotPruneAttribute" fullword ascii
      $s14 = "MemberRefsProxy" fullword ascii
      $s15 = "DoNotPruneTypeAttribute" fullword ascii
      $s16 = "SmartAssembly.Zip" fullword ascii
      $s17 = "Huahitec" fullword ascii
      $s18 = "GetCachedOrResource" fullword ascii
      $s19 = "<Killproc>b__5" fullword ascii
      $s20 = "<Killproc>b__4" fullword ascii
      $s21 = "PathLink" fullword ascii
   condition:
      uint16(0) == 0x5a4d and (all of ($a*) or all of ($x*) or 4 of ($s*))
}
