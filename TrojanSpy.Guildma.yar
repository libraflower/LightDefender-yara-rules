rule TrojanSpy_Guildma {
   meta:
      description = "TrojanSpy.Guildma"
      author = "LightDefender"
      date = "2021-08-01"
      hash1 = "067af8ade7c81784faed2fd8fda5dd791ee4157aff8013996329fe0efbb6442b"
   strings:
      $x1 = "C:\\Windows\\System32\\dllhost.exe" fullword ascii
      $x2 = "C:\\Windows\\SysWOW64\\dllhost.exe" fullword ascii
      $s3 = "C:\\Users\\Public\\go" fullword ascii
      $s4 = "C:\\Users\\Public\\k" fullword ascii
      $s5 = "C:\\Users\\Public\\r" fullword ascii
      $s6 = "C:\\Users\\Public\\l" fullword ascii
      $s7 = "C:\\Users\\Public\\prv\\" fullword ascii
      $s8 = "W9IGOQAS3W6RK2.dll" fullword ascii
      $s9 = "svchost" fullword ascii
      $s10 = "TCommonDialogP" fullword ascii
      $s11 = "OnGetSiteInfot" fullword ascii
      $s12 = "EInOutError$r@" fullword ascii
      $s13 = "%IdThreadMgr" fullword ascii
      $s14 = "AutoHotkeysh" fullword ascii
      $s15 = "IdThreadMgrDefault" fullword ascii
      $s16 = ":%:C:H:M:\\:a:f:u:z:" fullword ascii
      $s17 = "KeyPreview\\" fullword ascii
      $s18 = "TComponentNameP%A" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      1 of ($x*) and 4 of them
}
