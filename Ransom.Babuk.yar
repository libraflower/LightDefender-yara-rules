rule Ransom_Babuk {
   meta:
      description = "Ransom.Babuk"
      author = "LightDefender"
      date = "2021-06-27"
   strings:
      $mutex = "DoYouWantToHaveSexWithCuongDong" fullword ascii
      $mutex_api1 = "OpenMutexA" fullword ascii
      $mutex_api2 = "CreateMutexA" fullword ascii
      $delshadow1 = "/c vssadmin.exe delete shadows /all /quiet" wide
      $delshadow2 = "cmd.exe" wide
      $delshadow3 = "open" fullword wide
      $delshadow_api = "ShellExecuteW" fullword ascii
      $folder1 = "AppData" fullword wide
      $folder2 = "Boot" fullword wide
      $folder3 = "Windows.old" fullword wide
      $folder4 = "Tor Browser" fullword wide
      $folder5 = "$Recycle.Bin" fullword wide
      $note = "\\How To Restore Your Files.txt" fullword wide
      $encrypt = ".babyk" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (all of ($mutex*) or all of ($delshadow*) or all of ($folder*) or $note or $encrypt)
}
