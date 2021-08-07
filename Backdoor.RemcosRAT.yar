rule RemcosRAT_Aug_5 {
   meta:
      description = "Backdoor.RemcosRAT"
      author = "LightDefender"
      date = "2021-08-07"
      hash1 = "4b397487c62e45e2349920dc8fb905ebd85cf95bdde81fbb1f7e6ebdf3dbaea1"
      hash2 = "c64129ee795961963a0df968f6f460704f8bbe0622bea2e8958109a67e1c471a"
   strings:
      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
      $x2 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii
      $x3 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii
      $x4 = "C:\\WINDOWS\\system32\\userinit.exe" fullword ascii
      $s5 = "C:\\WINDOWS\\system32\\userinit.exe, " fullword ascii
      $s6 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" fullword ascii
      $s7 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii
      $s8 = "eventvwr.exe" fullword ascii
      $s9 = "PING 127.0.0.1 -n 2 " fullword ascii
      $s10 = "remscriptexecd" fullword ascii
      $s11 = "clearlogins" fullword ascii
      $s12 = "execcom" fullword ascii
      $s13 = "update.bat" fullword ascii
      $s14 = "autogetofflinelogs" fullword ascii
      $s15 = "getofflinelogs" fullword ascii
      $s16 = "mscfile\\shell\\open\\command" fullword ascii
      $s17 = "deletekeylog" fullword ascii
      $s18 = "\\logins.json" fullword ascii
      $s19 = "[Firefox StoredLogins not found]" fullword ascii
      $s20 = "[Chrome StoredLogins found, cleared!]" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and 1 of ($x*) and 4 of them
      ) or ( 12 of them )
}
