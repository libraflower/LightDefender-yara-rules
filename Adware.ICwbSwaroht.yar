rule Adware_ICwbSwaroht {
   meta:
      description = "Adware.ICwbSwaroht"
      author = "LightDefender"
      date = "2021-08-02"
      hash1 = "d026409df78b15226a4644e0a50612c02050a6b492efe7a1316679a66129ef32"
   strings:
      $s1 = "SvcHostDll.dll" fullword ascii
      $s2 = "C:\\log\\%s\\%s.txt" fullword wide
      $s3 = "SUserPage.exe" fullword wide
      $s4 = "SConfig.exe" fullword wide
      $s5 = "SService.exe" fullword wide
      $s6 = "SImeBrokerPS.dll" fullword wide
      $s7 = "SWordMgr.dll" fullword wide
      $s8 = "SImeBroker.exe" fullword wide
      $s9 = "SSkinInst.exe" fullword wide
      $s10 = "SDictInst.exe" fullword wide
      $s11 = "SCloud.exe" fullword wide
      $s12 = "SPlugin.exe" fullword wide
      $s13 = "SMBManager.exe" fullword wide
      $s14 = "SUpd.exe" fullword wide
      $s15 = "SMutual.exe" fullword wide
      $s16 = "SWizard.exe" fullword wide
      $s17 = "SImeManager.exe" fullword wide
      $s18 = "SRegIme64.exe" fullword wide
      $s19 = "SRegIme32.exe" fullword wide
      $s20 = "SImeRepair.exe" fullword wide
   condition:
      uint16(0) == 0x5a4d and
      8 of them
}
